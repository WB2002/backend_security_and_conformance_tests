package sast_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/runner"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/sast"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestSASTParsers(t *testing.T) {
	semgrepJSON := []byte(`{
		"results": [
			{
				"check_id": "go.lang.security.audit.jwt-hardcoded",
				"path": "/workspace/internal/auth/jwt.go",
				"start": { "line": 42, "col": 5 },
				"extra": {
					"severity": "ERROR",
					"message": "Hardcoded JWT secret detected",
					"metadata": { "cwe": ["CWE-798"] }
				}
			}
		]
	}`)
	findings, err := sast.ParseSemgrepOutput(semgrepJSON, "/workspace")
	if err != nil || len(findings) != 1 {
		t.Fatalf("semgrep parse failed: %v (len=%d)", err, len(findings))
	}
	if findings[0].FilePath != "internal/auth/jwt.go" || findings[0].Severity != types.SeverityHigh || findings[0].CWE != "CWE-798" {
		t.Fatalf("unexpected semgrep finding: %+v", findings[0])
	}

	gitleaksJSON := []byte(`[
		{
			"RuleID": "aws-access-token",
			"Description": "AWS Access Token",
			"File": "config/prod.exs",
			"StartLine": 19,
			"Fingerprint": "fp-123"
		}
	]`)
	gFindings, err := sast.ParseGitleaksOutput(gitleaksJSON, "")
	if err != nil || len(gFindings) != 1 || gFindings[0].Severity != types.SeverityCritical {
		t.Fatalf("gitleaks parse failed: %v %+v", err, gFindings)
	}

	trivyJSON := []byte(`{
		"Results": [
			{
				"Target": "Dockerfile",
				"Misconfigurations": [
					{
						"ID": "DS002",
						"Title": "Image user should not be root",
						"Description": "Running as root",
						"Severity": "HIGH",
						"CauseMetadata": { "StartLine": 14 }
					}
				],
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2025-1111",
						"PkgName": "lodash",
						"InstalledVersion": "4.17.15",
						"FixedVersion": "4.17.21",
						"Severity": "CRITICAL",
						"Title": "Prototype Pollution"
					}
				]
			}
		]
	}`)
	tFindings, err := sast.ParseTrivyFSOutput(trivyJSON, "")
	if err != nil || len(tFindings) != 2 {
		t.Fatalf("trivy parse failed: %v (len=%d)", err, len(tFindings))
	}
	if tFindings[0].Category != types.CategoryIaC || tFindings[1].CVE != "CVE-2025-1111" {
		t.Fatalf("unexpected trivy findings: %+v", tFindings)
	}
}

func TestRunSASTSuiteAutoModeAndErrorPropagation(t *testing.T) {
	if got := sast.NormalizeRelativePath("/Users/pc/repo/internal/a.go", "../repo"); got == "/Users/pc/repo/internal/a.go" {
		t.Fatalf("expected NormalizeRelativePath to handle relative targetDir")
	}
	_, err := sast.RunSASTSuite(context.Background(), "/tmp/repo", runner.ModeAuto, func(ctx context.Context, cmd runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		for _, a := range cmd.Args {
			if a == "/tmp/repo" && cmd.Mode == runner.ModeDocker {
				t.Fatalf("expected ModeAuto resolving to ModeDocker to pass /workspace, not host path %s", a)
			}
		}
		return runner.ToolExecutionResult{ExitCode: 2, Stderr: "fatal scanner error"}, nil
	})
	if err == nil {
		t.Fatalf("expected RunSASTSuite to return error when scanner fails with exit code 2")
	}
}

func TestRunSASTSuite_IncludesExclusionsAndGitleaksConfig(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".gitleaks.toml"), []byte("title = \"test\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var calls []runner.ResolvedCommand
	mockExec := func(ctx context.Context, cmd runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		calls = append(calls, cmd)
		return runner.ToolExecutionResult{ExitCode: 0, Stdout: "", OK: true, Mode: cmd.Mode}, nil
	}

	_, err := sast.RunSASTSuite(context.Background(), tmp, runner.ModeLocal, mockExec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("expected 3 tool calls, got %d", len(calls))
	}
	if !slices.Contains(calls[0].Args, "test/security/semgrep-fixtures") {
		t.Fatalf("expected semgrep args to exclude test/security/semgrep-fixtures, got %v", calls[0].Args)
	}
	if !slices.Contains(calls[1].Args, "--config") {
		t.Fatalf("expected gitleaks args to include --config when .gitleaks.toml exists, got %v", calls[1].Args)
	}
	if !slices.Contains(calls[2].Args, "--skip-dirs") {
		t.Fatalf("expected trivy args to include --skip-dirs, got %v", calls[2].Args)
	}
}


