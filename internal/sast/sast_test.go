package sast_test

import (
	"testing"

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
