package sast_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	if !slices.Contains(calls[0].Args, ".conformance-runner") {
		t.Fatalf("expected semgrep args to exclude .conformance-runner, got %v", calls[0].Args)
	}
	if !slices.Contains(calls[1].Args, "--config") {
		t.Fatalf("expected gitleaks args to include --config when .gitleaks.toml exists, got %v", calls[1].Args)
	}
	if !slices.Contains(calls[2].Args, "--skip-dirs") {
		t.Fatalf("expected trivy args to include --skip-dirs, got %v", calls[2].Args)
	}
	if !slices.Contains(calls[2].Args, "node_modules,dist,.git,.conformance-runner,.worktrees,.tsd-emit,coverage") {
		t.Fatalf("expected trivy --skip-dirs to exclude .conformance-runner/.worktrees/.tsd-emit/coverage without skipping tests, got %v", calls[2].Args)
	}
	if !slices.Contains(calls[1].Args, "--no-git") {
		t.Fatalf("expected gitleaks to pass --no-git when .git directory is absent, got %v", calls[1].Args)
	}
}

func TestGitleaksGitHistoryAndTrivyImageScan(t *testing.T) {
	gitRepo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(gitRepo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	var calls []runner.ResolvedCommand
	mockExec := func(ctx context.Context, cmd runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		calls = append(calls, cmd)
		return runner.ToolExecutionResult{ExitCode: 0, OK: true, Mode: cmd.Mode}, nil
	}

	if _, err := sast.RunSASTSuite(context.Background(), gitRepo, runner.ModeLocal, mockExec); err != nil {
		t.Fatalf("RunSASTSuite failed: %v", err)
	}
	if !slices.Contains(calls[0].Args, "--metrics=off") {
		t.Fatalf("expected semgrep --metrics=off, got %v", calls[0].Args)
	}
	if slices.Contains(calls[1].Args, "--no-git") {
		t.Fatalf("expected gitleaks to scan git history (no --no-git) when .git exists, got %v", calls[1].Args)
	}

	imgFindings, err := sast.RunTrivyImageScan(context.Background(), "acme/api:1.0.0", runner.ModeLocal, func(ctx context.Context, cmd runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		if !slices.Contains(cmd.Args, "image") || !slices.Contains(cmd.Args, "acme/api:1.0.0") {
			t.Fatalf("unexpected trivy image args: %v", cmd.Args)
		}
		return runner.ToolExecutionResult{
			ExitCode: 0,
			OK:       true,
			Stdout:   `{"Results":[{"Target":"acme/api:1.0.0 (alpine 3.20)","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","PkgName":"libcrypto3","Severity":"CRITICAL","Title":"OpenSSL RCE"}]}]}`,
		}, nil
	})
	if err != nil || len(imgFindings) != 1 || imgFindings[0].CVE != "CVE-2026-0001" {
		t.Fatalf("expected 1 critical image CVE finding, got %+v (err=%v)", imgFindings, err)
	}
}

func TestRunTrivyImageScan_ParsesSecrets(t *testing.T) {
	trivySecretJSON := `{
		"Results": [
			{
				"Target": "app/.env",
				"Secrets": [
					{
						"RuleID": "aws-access-key-id",
						"Category": "AWS",
						"Severity": "CRITICAL",
						"Title": "AWS Access Key ID",
						"StartLine": 7,
						"Match": "AWS_ACCESS_KEY_ID=AKIA****************"
					}
				]
			}
		]
	}`

	findings, err := sast.RunTrivyImageScan(context.Background(), "acme/api:1.0.0", runner.ModeLocal, func(ctx context.Context, cmd runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		return runner.ToolExecutionResult{
			ExitCode: 0,
			OK:       true,
			Stdout:   trivySecretJSON,
		}, nil
	})
	if err != nil {
		t.Fatalf("RunTrivyImageScan returned unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 secret finding from Trivy image scan, got %d (%+v)", len(findings), findings)
	}
	f := findings[0]
	if f.Category != types.CategorySecret {
		t.Fatalf("expected CategorySecret, got %q", f.Category)
	}
	if f.Tool != "trivy" {
		t.Fatalf("expected Tool=trivy, got %q", f.Tool)
	}
	if f.Severity != types.SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %q", f.Severity)
	}
	if f.FilePath != "app/.env" || f.Line != 7 {
		t.Fatalf("expected FilePath=app/.env Line=7, got %q:%d", f.FilePath, f.Line)
	}
	if f.Title != "AWS Access Key ID" || f.ID != "trivy-secret-aws-access-key-id-1" {
		t.Fatalf("expected Title and ID containing RuleID, got Title=%q ID=%q", f.Title, f.ID)
	}
	if f.CWE != "CWE-798" {
		t.Fatalf("expected CWE-798 for secret finding, got %q", f.CWE)
	}
}

func TestParseSemgrepOutput_ExtractsTaintDataflowTrace(t *testing.T) {
	semgrepJSON := []byte(`{
  "results": [
    {
      "check_id": "conformance.taint.sql-injection",
      "path": "/workspace/src/controllers/user.ts",
      "start": { "line": 27, "col": 9 },
      "extra": {
        "severity": "ERROR",
        "message": "Unsanitized user input flows to SQL query",
        "metadata": { "cwe": ["CWE-89: SQL Injection"] },
        "dataflow_trace": {
          "taint_source": [
            "CliLoc",
            [
              {
                "path": "/workspace/src/controllers/user.ts",
                "start": { "line": 12, "col": 18 }
              },
              "req.query.id"
            ]
          ],
          "intermediate_vars": [
            {
              "location": {
                "path": "/workspace/src/controllers/user.ts",
                "start": { "line": 18, "col": 7 }
              },
              "content": "userId"
            }
          ],
          "taint_sink": [
            "CliLoc",
            [
              {
                "path": "/workspace/src/controllers/user.ts",
                "start": { "line": 27, "col": 9 }
              },
              "db.query(\"SELECT * FROM users WHERE id = \" + userId)"
            ]
          ]
        }
      }
    }
  ]
}`)

	findings, err := sast.ParseSemgrepOutput(semgrepJSON, "/workspace")
	if err != nil {
		t.Fatalf("ParseSemgrepOutput failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if len(f.CodeFlows) != 1 {
		t.Fatalf("expected 1 CodeFlow, got %d (%+v)", len(f.CodeFlows), f.CodeFlows)
	}
	steps := f.CodeFlows[0]
	if len(steps) != 3 {
		t.Fatalf("expected 3 CodeFlowSteps, got %d (%+v)", len(steps), steps)
	}
	if steps[0].Kind != "source" || steps[0].Line != 12 || steps[0].FilePath != "src/controllers/user.ts" {
		t.Fatalf("unexpected source step: %+v", steps[0])
	}
	if steps[1].Kind != "propagator" || steps[1].Line != 18 || steps[1].FilePath != "src/controllers/user.ts" {
		t.Fatalf("unexpected propagator step: %+v", steps[1])
	}
	if steps[2].Kind != "sink" || steps[2].Line != 27 || steps[2].FilePath != "src/controllers/user.ts" {
		t.Fatalf("unexpected sink step: %+v", steps[2])
	}
}

func TestParsePolyglotScanners_GosecGovulncheckBanditSobelow(t *testing.T) {
	gosecJSON := []byte(`{
		"Issues": [
			{
				"severity": "HIGH",
				"confidence": "HIGH",
				"cwe": { "id": "89", "url": "https://cwe.mitre.org/data/definitions/89.html" },
				"rule_id": "G201",
				"details": "SQL string formatting",
				"file": "/workspace/internal/repo/user.go",
				"line": "44",
				"column": "10"
			}
		]
	}`)
	gosecFindings, err := sast.ParseGosecOutput(gosecJSON, "/workspace")
	if err != nil || len(gosecFindings) != 1 {
		t.Fatalf("ParseGosecOutput failed: err=%v findings=%+v", err, gosecFindings)
	}
	if gosecFindings[0].Category != types.CategorySAST || gosecFindings[0].Severity != types.SeverityHigh || gosecFindings[0].CWE != "CWE-89" || gosecFindings[0].Line != 44 {
		t.Fatalf("unexpected gosec finding: %+v", gosecFindings[0])
	}

	govulncheckStream := []byte(`{
		"osv": {
			"id": "GO-2025-1234",
			"aliases": ["CVE-2025-9999"],
			"summary": "HTTP request smuggling in example/pkg"
		}
	}
	{
		"finding": {
			"osv": "GO-2025-1234",
			"fixed_version": "v1.4.2",
			"trace": [
				{
					"module": "example.com/pkg",
					"version": "v1.4.1",
					"package": "example.com/pkg/http",
					"function": "ParseRequest",
					"position": {
						"filename": "/workspace/vendor/pkg/http.go",
						"line": 88,
						"column": 4
					}
				},
				{
					"module": "example.com/app",
					"package": "example.com/app/handler",
					"function": "HandleAPI",
					"position": {
						"filename": "/workspace/internal/handler/api.go",
						"line": 21,
						"column": 12
					}
				}
			]
		}
	}`)
	gvFindings, err := sast.ParseGovulncheckOutput(govulncheckStream, "/workspace")
	if err != nil || len(gvFindings) != 1 {
		t.Fatalf("ParseGovulncheckOutput failed: err=%v findings=%+v", err, gvFindings)
	}
	if gvFindings[0].Category != types.CategorySCA || gvFindings[0].CVE != "CVE-2025-9999" {
		t.Fatalf("unexpected govulncheck finding: %+v", gvFindings[0])
	}
	if gvFindings[0].Reachable == nil || !*gvFindings[0].Reachable {
		t.Fatalf("expected govulncheck finding to have Reachable=true, got %+v", gvFindings[0].Reachable)
	}
	if len(gvFindings[0].CodeFlows) != 1 || len(gvFindings[0].CodeFlows[0]) != 2 {
		t.Fatalf("expected 1 CodeFlow with 2 steps from govulncheck trace, got %+v", gvFindings[0].CodeFlows)
	}

	banditJSON := []byte(`{
		"results": [
			{
				"test_id": "B608",
				"test_name": "hardcoded_sql_expressions",
				"issue_severity": "HIGH",
				"issue_confidence": "HIGH",
				"issue_text": "Possible SQL injection vector through string-based query construction.",
				"filename": "/workspace/app/tasks.py",
				"line_number": 31,
				"issue_cwe": { "id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html" }
			}
		]
	}`)
	banditFindings, err := sast.ParseBanditOutput(banditJSON, "/workspace")
	if err != nil || len(banditFindings) != 1 {
		t.Fatalf("ParseBanditOutput failed: err=%v findings=%+v", err, banditFindings)
	}
	if banditFindings[0].Category != types.CategorySAST || banditFindings[0].Severity != types.SeverityHigh || banditFindings[0].CWE != "CWE-89" || banditFindings[0].Line != 31 {
		t.Fatalf("unexpected bandit finding: %+v", banditFindings[0])
	}

	sobelowJSON := []byte(`{
		"findings": {
			"high_confidence": [
				{
					"type": "SQL.Query: SQL injection",
					"file": "lib/app_web/controllers/user_controller.ex",
					"line": 52
				}
			],
			"medium_confidence": [],
			"low_confidence": []
		}
	}`)
	sobelowFindings, err := sast.ParseSobelowOutput(sobelowJSON, "/workspace")
	if err != nil || len(sobelowFindings) != 1 {
		t.Fatalf("ParseSobelowOutput failed: err=%v findings=%+v", err, sobelowFindings)
	}
	if sobelowFindings[0].Category != types.CategorySAST || sobelowFindings[0].Severity != types.SeverityHigh || sobelowFindings[0].CWE != "CWE-89" || sobelowFindings[0].Line != 52 {
		t.Fatalf("unexpected sobelow finding: %+v", sobelowFindings[0])
	}
}

func TestRunSASTSuite_UsesOfflineEmbeddedRulesAndDoesNotSkipTestsInTrivy(t *testing.T) {
	tmp := t.TempDir()
	var calls []runner.ResolvedCommand
	mockExec := func(ctx context.Context, cmd runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		calls = append(calls, cmd)
		return runner.ToolExecutionResult{ExitCode: 0, Stdout: "", OK: true, Mode: cmd.Mode}, nil
	}

	_, err := sast.RunSASTSuiteWithOptions(context.Background(), tmp, "", runner.ModeDocker, mockExec)
	if err != nil {
		t.Fatalf("RunSASTSuiteWithOptions failed: %v", err)
	}
	if len(calls) < 3 {
		t.Fatalf("expected at least 3 tool calls, got %d", len(calls))
	}

	semgrepArgs := calls[0].Args
	if slices.Contains(semgrepArgs, "auto") {
		t.Fatalf("expected semgrep NOT to use '--config auto', got %v", semgrepArgs)
	}
	if !slices.Contains(semgrepArgs, "--metrics=off") {
		t.Fatalf("expected semgrep to pass --metrics=off, got %v", semgrepArgs)
	}
	if !slices.Contains(semgrepArgs, "/out/rules") {
		t.Fatalf("expected semgrep in docker mode to use embedded rules at /out/rules, got %v", semgrepArgs)
	}
	if !slices.Contains(semgrepArgs, "--network=none") {
		t.Fatalf("expected semgrep docker invocation to enforce --network=none, got %v", semgrepArgs)
	}

	trivyArgs := calls[2].Args
	skipIdx := slices.Index(trivyArgs, "--skip-dirs")
	if skipIdx < 0 || skipIdx+1 >= len(trivyArgs) {
		t.Fatalf("expected trivy --skip-dirs flag, got %v", trivyArgs)
	}
	skipDirs := strings.Split(trivyArgs[skipIdx+1], ",")
	if slices.Contains(skipDirs, "test") || slices.Contains(skipDirs, "tests") {
		t.Fatalf("trivy --skip-dirs must NOT skip test or tests directories, got %v", skipDirs)
	}
}

func TestWriteEmbeddedSemgrepRulesAndPureGoScanners(t *testing.T) {
	outDir := t.TempDir()
	rulesDir, err := sast.WriteEmbeddedSemgrepRules(outDir)
	if err != nil {
		t.Fatalf("WriteEmbeddedSemgrepRules failed: %v", err)
	}
	for _, name := range []string{"conformance-invariants.yaml", "taint-flows.yaml"} {
		info, statErr := os.Stat(filepath.Join(rulesDir, name))
		if statErr != nil || info.Size() == 0 {
			t.Fatalf("expected non-empty embedded rule file %s, err=%v", name, statErr)
		}
	}

	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "shallow"), []byte("deadbeef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".env.production"), []byte("JWT_SECRET=prod\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".env.example"), []byte("JWT_SECRET=changeme\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	hygiene, err := sast.ScanGitRepoHygiene(repo)
	if err != nil {
		t.Fatalf("ScanGitRepoHygiene failed: %v", err)
	}
	if len(hygiene) != 2 {
		t.Fatalf("expected 2 hygiene findings (shallow + .env.production, ignoring .env.example), got %d: %+v", len(hygiene), hygiene)
	}
	if hygiene[0].Category != types.CategorySupplyChain || hygiene[0].Severity != types.SeverityMedium {
		t.Fatalf("unexpected shallow clone finding: %+v", hygiene[0])
	}
	if hygiene[1].Category != types.CategorySecret || hygiene[1].Severity != types.SeverityHigh {
		t.Fatalf("unexpected .env finding: %+v", hygiene[1])
	}

	tsDir := filepath.Join(repo, "src", "auth")
	if err := os.MkdirAll(tsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tsDir, "guard.ts"), []byte("// @ts-ignore\nconst u = req.user as any;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tsFindings, err := sast.ScanTypeScriptBoundarySafety(repo)
	if err != nil {
		t.Fatalf("ScanTypeScriptBoundarySafety failed: %v", err)
	}
	if len(tsFindings) != 2 {
		t.Fatalf("expected 2 ts-boundary findings, got %d: %+v", len(tsFindings), tsFindings)
	}

	yaraFindings, err := sast.ParseYARAOutput([]byte("SampleIndicatorRule /workspace/scripts/helper.js\n"), "/workspace")
	if err != nil || len(yaraFindings) != 1 || yaraFindings[0].Category != types.CategoryMalware || yaraFindings[0].Severity != types.SeverityCritical {
		t.Fatalf("unexpected yara findings: err=%v findings=%+v", err, yaraFindings)
	}
}
