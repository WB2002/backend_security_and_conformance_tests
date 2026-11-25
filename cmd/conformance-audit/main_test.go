package main

import (
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/runner"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestBuildDASTOptions_RequireOpenAPIOnAllStages(t *testing.T) {
	m := types.BoilerplateManifest{
		Name:       "test-api",
		OpenAPIURL: "/openapi.json",
	}

	tests := []struct {
		name               string
		stagesFlag         string
		wantDASTEnabled    bool
		wantRequireOpenAPI bool
	}{
		{
			name:               "explicit dast stage requires OpenAPI",
			stagesFlag:         "supplychain,dast",
			wantDASTEnabled:    true,
			wantRequireOpenAPI: true,
		},
		{
			name:               "all stages keeps fail-closed RequireOpenAPI",
			stagesFlag:         "all",
			wantDASTEnabled:    true,
			wantRequireOpenAPI: true,
		},
		{
			name:               "ALL uppercase trimmed keeps fail-closed RequireOpenAPI",
			stagesFlag:         " ALL ",
			wantDASTEnabled:    true,
			wantRequireOpenAPI: true,
		},
		{
			name:               "sast only disables DAST and RequireOpenAPI",
			stagesFlag:         "sast",
			wantDASTEnabled:    false,
			wantRequireOpenAPI: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stages := parseStages(tc.stagesFlag)
			if got := stageEnabled(stages, "dast"); got != tc.wantDASTEnabled {
				t.Fatalf("stageEnabled(%q, dast) = %v, want %v", tc.stagesFlag, got, tc.wantDASTEnabled)
			}
			opts := buildDASTOptions("http://127.0.0.1:3000", m, "tok-1", stages, runner.ModeLocal)
			if opts.RequireOpenAPI != tc.wantRequireOpenAPI {
				t.Fatalf("RequireOpenAPI for stages %q = %v, want %v", tc.stagesFlag, opts.RequireOpenAPI, tc.wantRequireOpenAPI)
			}
		})
	}
}
