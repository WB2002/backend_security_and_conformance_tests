package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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

func TestApplySecurityWaivers_ValidationAndMatchingTable(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	validExp := "2026-12-31T00:00:00Z"

	tests := []struct {
		name                string
		finding             types.SecurityFinding
		waiver              types.SecurityWaiver
		wantRetained        bool
		wantViolationSubstr string
	}{
		{
			name:    "malformed expiresAt",
			finding: types.SecurityFinding{ID: "sast-1", Category: types.CategorySAST, Severity: types.SeverityHigh},
			waiver: types.SecurityWaiver{
				FindingID:     "sast-1",
				Justification: "Verified safe",
				ApprovedBy:    "sec-team",
				ExpiresAt:     "not-a-date",
			},
			wantRetained:        true,
			wantViolationSubstr: "must be valid RFC3339",
		},
		{
			name:    "missing justification",
			finding: types.SecurityFinding{ID: "sast-2", Category: types.CategorySAST, Severity: types.SeverityHigh},
			waiver: types.SecurityWaiver{
				FindingID:     "sast-2",
				Justification: "   ",
				ApprovedBy:    "sec-team",
				ExpiresAt:     validExp,
			},
			wantRetained:        true,
			wantViolationSubstr: "missing justification",
		},
		{
			name:    "missing approvedBy",
			finding: types.SecurityFinding{ID: "sast-3", Category: types.CategorySAST, Severity: types.SeverityHigh},
			waiver: types.SecurityWaiver{
				FindingID:     "sast-3",
				Justification: "Verified safe",
				ApprovedBy:    "",
				ExpiresAt:     validExp,
			},
			wantRetained:        true,
			wantViolationSubstr: "missing approvedBy",
		},
		{
			name:    "RuleOrCVE matches CVE with surrounding whitespace",
			finding: types.SecurityFinding{ID: "sca-1", CVE: "CVE-2026-4242", Category: types.CategorySCA, Severity: types.SeverityHigh},
			waiver: types.SecurityWaiver{
				RuleOrCVE:     "  CVE-2026-4242  ",
				Justification: "Not reachable in runtime path",
				ApprovedBy:    "sec-team",
				ExpiresAt:     validExp,
			},
			wantRetained: false,
		},
		{
			name:    "RuleOrCVE matches finding ID",
			finding: types.SecurityFinding{ID: "semgrep-rule-99", Category: types.CategorySAST, Severity: types.SeverityMedium},
			waiver: types.SecurityWaiver{
				RuleOrCVE:     "semgrep-rule-99",
				Justification: "False positive",
				ApprovedBy:    "sec-team",
				ExpiresAt:     validExp,
			},
			wantRetained: false,
		},
		{
			name:    "FindingID matches with surrounding whitespace",
			finding: types.SecurityFinding{ID: "sast-trim-1", Category: types.CategorySAST, Severity: types.SeverityHigh},
			waiver: types.SecurityWaiver{
				FindingID:     "  sast-trim-1  ",
				Justification: "Verified safe",
				ApprovedBy:    "sec-team",
				ExpiresAt:     validExp,
			},
			wantRetained: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			card := types.ConformanceScorecard{
				TargetName: "app",
				Language:   types.LangGo,
				Findings:   []types.SecurityFinding{tc.finding},
			}
			wf := types.WaiverFile{Waivers: []types.SecurityWaiver{tc.waiver}}

			filtered, violations := policy.ApplySecurityWaivers(card, wf, now)
			if tc.wantRetained && len(filtered.Findings) != 1 {
				t.Fatalf("expected finding retained, got %+v", filtered.Findings)
			}
			if !tc.wantRetained && len(filtered.Findings) != 0 {
				t.Fatalf("expected finding suppressed, got %+v", filtered.Findings)
			}
			if tc.wantViolationSubstr != "" {
				if len(violations) == 0 || !strings.Contains(strings.Join(violations, "; "), tc.wantViolationSubstr) {
					t.Fatalf("expected violation containing %q, got %v", tc.wantViolationSubstr, violations)
				}
			} else if len(violations) != 0 {
				t.Fatalf("expected 0 violations, got %v", violations)
			}
		})
	}
}

func TestEvaluateSecurityPolicy_ExtendedGates(t *testing.T) {
	pol := policy.StrictSecurityPolicy()
	card := types.ConformanceScorecard{
		SourceGraph: types.DependencyGraph{
			LayerViolations: []types.LayerViolation{{ID: "layer-1", FromLayer: "controller", ToLayer: "db", Severity: types.SeverityHigh}},
			RouteFindings: []types.RouteGuardFinding{
				{ID: "route-unprotected-1", Kind: "unprotected-route", Method: "POST", Path: "/orders", MissingGuards: []string{"auth"}, Severity: types.SeverityHigh},
				{ID: "route-shadow-1", Kind: "shadow-route", Method: "DELETE", Path: "/internal/wipe", Severity: types.SeverityHigh},
			},
		},
		MemoryAnalysis: &types.MemoryLeakAnalysis{
			RetainedDriftPercent: 22.5,
			SlopeBytesPerReq:     2048,
			FDDelta:              64,
			GoroutineDelta:       50,
			LeakDetected:         true,
		},
		EgressViolations: []types.EgressViolation{{RemoteAddr: "198.51.100.99:4444", Process: "sh", Reason: "unexpected outbound connection"}},
	}

	res := policy.EvaluateSecurityPolicy(card, pol)
	if res.Passed {
		t.Fatalf("expected policy failure, got Passed=true")
	}
	for _, wantSub := range []string{
		"layer boundary violation",
		"unprotected route",
		"undocumented shadow route",
		"retained memory drift",
		"file descriptor growth",
		"goroutine growth",
		"unexpected runtime egress",
	} {
		if !slices.ContainsFunc(res.Violations, func(v string) bool { return strings.Contains(v, wantSub) }) {
			t.Errorf("expected violation containing %q in %v", wantSub, res.Violations)
		}
	}
}

func TestLoadPolicyFileClampsEgressViolations(t *testing.T) {
	tmpDir := t.TempDir()
	polPath := filepath.Join(tmpDir, "policy.json")
	polRaw := `{"maxMalwareFindings":3,"maxEgressViolations":10}`
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
	if pol.MaxEgressViolations != 0 {
		t.Fatalf("expected MaxEgressViolations clamped to 0, got %d", pol.MaxEgressViolations)
	}
}

func TestEvaluateSecurityPolicy_MemoryBackwardCompatibilityAndSlope(t *testing.T) {
	pol := policy.StrictSecurityPolicy()

	// Legacy MemoryLeakAnalysis with PostWarmupBaselineBytes == 0 and LeakDetected == false should NOT fail on DriftPercent alone.
	cleanLegacy := types.ConformanceScorecard{
		MemoryAnalysis: &types.MemoryLeakAnalysis{
			InitialRSSBytes: 100_000_000,
			FinalRSSBytes:   125_000_000,
			DriftPercent:    25.0,
			LeakDetected:    false,
		},
	}
	if res := policy.EvaluateSecurityPolicy(cleanLegacy, pol); !res.Passed {
		t.Fatalf("expected legacy scorecard with LeakDetected=false to pass, got %v", res.Violations)
	}

	// Legacy MemoryLeakAnalysis with PostWarmupBaselineBytes == 0 and LeakDetected == true + DriftPercent > MaxMemoryDriftPercent should fail.
	leakLegacy := types.ConformanceScorecard{
		MemoryAnalysis: &types.MemoryLeakAnalysis{
			InitialRSSBytes: 100_000_000,
			FinalRSSBytes:   130_000_000,
			DriftPercent:    30.0,
			LeakDetected:    true,
		},
	}
	if res := policy.EvaluateSecurityPolicy(leakLegacy, pol); res.Passed {
		t.Fatalf("expected legacy scorecard with LeakDetected=true to fail")
	}

	// SlopeBytesPerReq exceeding MaxMemorySlopeBytesPerReq should fail even if RetainedDriftPercent is below threshold.
	slopeCard := types.ConformanceScorecard{
		MemoryAnalysis: &types.MemoryLeakAnalysis{
			PostWarmupBaselineBytes: 100_000_000,
			RetainedDriftPercent:    5.0,
			SlopeBytesPerReq:        2048.0,
		},
	}
	res := policy.EvaluateSecurityPolicy(slopeCard, pol)
	if res.Passed {
		t.Fatalf("expected slope violation to fail policy")
	}
	if !slices.ContainsFunc(res.Violations, func(v string) bool { return strings.Contains(v, "memory slope") }) {
		t.Errorf("expected memory slope violation, got %v", res.Violations)
	}
}

func TestEvaluateSecurityPolicy_FailsOnBeamAtomGrowthOver1MiB(t *testing.T) {
	pol := policy.StrictSecurityPolicy()

	// Within 1 MiB threshold should pass.
	okCard := types.ConformanceScorecard{
		MemoryAnalysis: &types.MemoryLeakAnalysis{
			PostWarmupBaselineBytes: 50 * 1024 * 1024,
			RetainedDriftPercent:    1.0,
			SlopeBytesPerReq:        10.0,
			BeamAtomDeltaBytes:      1024 * 1024,
			LeakDetected:            false,
		},
	}
	if res := policy.EvaluateSecurityPolicy(okCard, pol); !res.Passed {
		t.Fatalf("expected BeamAtomDeltaBytes == 1 MiB to pass, got %v", res.Violations)
	}

	// Exceeding 1 MiB must fail StrictSecurityPolicy even with flat RSS/FDs/goroutines.
	leakCard := types.ConformanceScorecard{
		MemoryAnalysis: &types.MemoryLeakAnalysis{
			PostWarmupBaselineBytes: 50 * 1024 * 1024,
			RetainedDriftPercent:    0.5,
			SlopeBytesPerReq:        0.0,
			BeamAtomDeltaBytes:      2 * 1024 * 1024,
			LeakDetected:            true,
		},
	}
	res := policy.EvaluateSecurityPolicy(leakCard, pol)
	if res.Passed {
		t.Fatalf("expected BEAM atom growth > 1 MiB to fail StrictSecurityPolicy, got Passed=true")
	}
	if !slices.ContainsFunc(res.Violations, func(v string) bool { return strings.Contains(strings.ToLower(v), "beam atom") }) {
		t.Fatalf("expected BEAM atom violation message, got %v", res.Violations)
	}
}

func TestManifestExtendedCapabilitiesAndDefaults(t *testing.T) {
	raw := []byte(`{
		"name": "go-full-api",
		"language": "go",
		"capabilities": {
			"health": { "path": "/healthz" },
			"graphql": { "enabled": true },
			"upload": { "enabled": true, "path": "/api/upload" },
			"diagnostics": {
				"enabled": true,
				"pprofBaseUrl": "/debug/pprof",
				"runtimeStatsUrl": "/debug/stats",
				"gcTriggerUrl": "/debug/gc"
			}
		},
		"architecture": {
			"layers": [
				{ "name": "controller", "pathPrefixes": ["internal/http/"] },
				{ "name": "db", "pathPrefixes": ["internal/db/"] }
			],
			"forbiddenFlows": [
				{ "from": "controller", "to": "db", "reason": "must go through service layer" }
			],
			"publicRoutes": ["/healthz", "/api/auth/login"],
			"requireAuthOnNonPublic": true,
			"requireRateLimitOnNonPublic": true,
			"requireValidationOnMutating": true
		}
	}`)

	m, err := manifest.ParseAndValidateManifest(raw)
	if err != nil {
		t.Fatalf("expected valid extended manifest, got error: %v", err)
	}
	if m.Capabilities.GraphQL == nil || m.Capabilities.GraphQL.Path != "/graphql" {
		t.Fatalf("expected default GraphQL.Path=/graphql, got %+v", m.Capabilities.GraphQL)
	}
	if m.Capabilities.Upload == nil || m.Capabilities.Upload.FieldName != "file" {
		t.Fatalf("expected default Upload.FieldName=file, got %+v", m.Capabilities.Upload)
	}
	if m.Capabilities.Diagnostics == nil || !m.Capabilities.Diagnostics.Enabled || m.Capabilities.Diagnostics.PprofBaseURL != "/debug/pprof" {
		t.Fatalf("unexpected diagnostics capability: %+v", m.Capabilities.Diagnostics)
	}
	if m.Architecture == nil || len(m.Architecture.Layers) != 2 || len(m.Architecture.ForbiddenFlows) != 1 || !m.Architecture.RequireAuthOnNonPublic {
		t.Fatalf("unexpected architecture rules: %+v", m.Architecture)
	}
}
