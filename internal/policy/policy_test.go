package policy_test

import (
	"encoding/json"
	"strings"
	"testing"

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

