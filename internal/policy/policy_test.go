package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/manifest"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/policy"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestManifestValidationAndExtractByPath(t *testing.T) {
	raw := []byte(`{
		"name": "elixir-phoenix-api",
		"language": "elixir",
		"openapiUrl": "/api/openapi.json",
		"capabilities": {
			"health": { "method": "GET", "path": "/health" },
			"auth": {
				"register": { "method": "POST", "path": "/api/v1/auth/register", "emailField": "email", "passwordField": "password" },
				"login": { "method": "POST", "path": "/api/v1/auth/login", "emailField": "email", "passwordField": "password", "tokenPath": "$.data.accessToken", "refreshPath": "data.refreshToken" },
				"me": { "method": "GET", "path": "/api/v1/users/me", "userIdPath": "data.id" }
			}
		}
	}`)
	m, err := manifest.ParseAndValidateManifest(raw)
	if err != nil {
		t.Fatalf("expected valid manifest, got error: %v", err)
	}
	if m.Name != "elixir-phoenix-api" || m.Language != types.LangElixir {
		t.Fatalf("unexpected manifest fields: %+v", m)
	}

	_, err = manifest.ParseAndValidateManifest([]byte(`{"name":"bad","language":"cobol","capabilities":{}}`))
	if err == nil {
		t.Fatalf("expected error for unsupported language and missing health capability")
	}

	var payload any
	_ = json.Unmarshal([]byte(`{"data":{"tokens":{"access":"jwt-999"},"id":"u-42"}}`), &payload)
	if val, ok := manifest.ExtractByPath(payload, "$.data.tokens.access"); !ok || val != "jwt-999" {
		t.Fatalf("expected jwt-999, got %v (ok=%v)", val, ok)
	}
}

func TestStrictSecurityPolicyEvaluation(t *testing.T) {
	card := types.ConformanceScorecard{
		TargetName: "go-boilerplate",
		Language:   types.LangGo,
	}
	res := policy.EvaluateSecurityPolicy(card, policy.StrictSecurityPolicy())
	if !res.Passed || len(res.Violations) != 0 {
		t.Fatalf("expected clean scorecard to pass, got %+v", res)
	}

	card.SourceGraph.Cycles = append(card.SourceGraph.Cycles, types.CycleFinding{
		ID:        "cycle-1",
		GraphType: "source",
		Nodes:     []string{"internal/auth/a.go", "internal/user/u.go", "internal/auth/a.go"},
		IsToxic:   false,
		Severity:  types.SeverityMedium,
	})
	card.Findings = append(card.Findings, types.SecurityFinding{
		ID:       "sast-1",
		Category: types.CategorySAST,
		Tool:     "semgrep",
		Severity: types.SeverityHigh,
		Title:    "Hardcoded secret",
	})
	card.PenTestResults = append(card.PenTestResults, types.PenTestCheckResult{
		ID:       "bola-1",
		Name:     "BOLA check",
		Status:   "failed",
		Severity: types.SeverityCritical,
	})

	res = policy.EvaluateSecurityPolicy(card, policy.StrictSecurityPolicy())
	if res.Passed || len(res.Violations) < 3 {
		t.Fatalf("expected policy failure with >=3 violations, got %+v", res)
	}
	if !strings.Contains(strings.ToLower(strings.Join(res.Violations, " ")), "cycle") {
		t.Fatalf("expected cycle violation message, got %v", res.Violations)
	}
}

func TestSecurityWaiversAndNonWaivableMalware(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	card := types.ConformanceScorecard{
		TargetName: "app",
		Language:   types.LangGo,
		Findings: []types.SecurityFinding{
			{ID: "semgrep-fp-1", Category: types.CategorySAST, Severity: types.SeverityHigh, Title: "False positive"},
			{ID: "mal-1", Category: types.CategoryMalware, Severity: types.SeverityCritical, CVE: "MAL-2026-0001", Title: "Malicious package"},
		},
		LoadTest: &types.LoadTestSummary{Profile: "soak", Passed: true},
	}

	// Valid waiver suppresses SAST finding, expired waiver triggers violation, and malware waiver is forbidden!
	wf := types.WaiverFile{
		Waivers: []types.SecurityWaiver{
			{FindingID: "semgrep-fp-1", Justification: "Verified safe wrapper", ApprovedBy: "sec-team", ExpiresAt: "2026-12-31T00:00:00Z"},
			{FindingID: "mal-1", Justification: "Try waiving malware", ApprovedBy: "rogue", ExpiresAt: "2026-12-31T00:00:00Z"},
			{FindingID: "old-finding", Justification: "Old waiver", ApprovedBy: "sec-team", ExpiresAt: "2026-10-01T00:00:00Z"},
		},
	}

	filtered, waiverErrs := policy.ApplySecurityWaivers(card, wf, now)
	if len(filtered.Findings) != 1 || filtered.Findings[0].Category != types.CategoryMalware {
		t.Fatalf("expected SAST finding waived and Malware finding retained, got %+v", filtered.Findings)
	}
	if len(waiverErrs) != 2 {
		t.Fatalf("expected 2 waiver violations (malware non-waivable + expired waiver), got %v", waiverErrs)
	}

	// Soak profile without MemoryAnalysis must fail when RequireMemoryOnSoak is true
	res := policy.EvaluateSecurityPolicy(filtered, policy.StrictSecurityPolicy())
	if res.Passed || !strings.Contains(strings.Join(res.Violations, " "), "malware") || !strings.Contains(strings.Join(res.Violations, " "), "memory") {
		t.Fatalf("expected malware + soak memory violations, got %+v", res)
	}
}

func TestLoadPolicyFileClampsMalwareAndLoadWaiverFile(t *testing.T) {
	tmpDir := t.TempDir()

	polPath := filepath.Join(tmpDir, "policy.json")
	polRaw := `{"failOnAnySourceCycle":false,"maxCriticalFindings":2,"maxMalwareFindings":5,"requireMemoryOnSoak":true}`
	if err := os.WriteFile(polPath, []byte(polRaw), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	pol, err := policy.LoadPolicyFile(polPath)
	if err != nil {
		t.Fatalf("LoadPolicyFile failed: %v", err)
	}
	if pol.MaxMalwareFindings != 0 {
		t.Fatalf("expected MaxMalwareFindings clamped to 0, got %d", pol.MaxMalwareFindings)
	}
	if pol.MaxCriticalFindings != 2 || !pol.RequireMemoryOnSoak {
		t.Fatalf("unexpected loaded policy: %+v", pol)
	}

	waiverPath := filepath.Join(tmpDir, "waivers.json")
	waiverRaw := `{"waivers":[{"findingId":"sast-1","ruleOrCve":"CVE-2026-1234","justification":"Mitigated","approvedBy":"sec","expiresAt":"2026-12-31T00:00:00Z"}]}`
	if err := os.WriteFile(waiverPath, []byte(waiverRaw), 0644); err != nil {
		t.Fatalf("write waivers: %v", err)
	}
	wf, err := policy.LoadWaiverFile(waiverPath)
	if err != nil {
		t.Fatalf("LoadWaiverFile failed: %v", err)
	}
	if len(wf.Waivers) != 1 || wf.Waivers[0].FindingID != "sast-1" || wf.Waivers[0].RuleOrCVE != "CVE-2026-1234" {
		t.Fatalf("unexpected loaded waivers: %+v", wf)
	}
}

