package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/load"
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

func TestResolvePhaseDurations(t *testing.T) {
	w, c := resolvePhaseDurations(load.ProfileBaseline, false, false, 0, 0)
	if w != 5*time.Second || c != 5*time.Second {
		t.Fatalf("baseline defaults = (%v, %v), want (5s, 5s)", w, c)
	}
	w, c = resolvePhaseDurations(load.ProfileStress, false, false, 0, 0)
	if w != 5*time.Second || c != 5*time.Second {
		t.Fatalf("stress defaults = (%v, %v), want (5s, 5s)", w, c)
	}
	w, c = resolvePhaseDurations(load.ProfileSoak, false, false, 0, 0)
	if w != 20*time.Second || c != 30*time.Second {
		t.Fatalf("soak defaults = (%v, %v), want (20s, 30s)", w, c)
	}
	w, c = resolvePhaseDurations(load.ProfileSoak, true, true, 12*time.Second, 18*time.Second)
	if w != 12*time.Second || c != 18*time.Second {
		t.Fatalf("explicit overrides = (%v, %v), want (12s, 18s)", w, c)
	}
}

func TestRunStaticGraphStage_ArchitectureAndLeakSAST(t *testing.T) {
	repo := t.TempDir()
	mustWrite := func(rel, content string) {
		t.Helper()
		full := filepath.Join(repo, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mustWrite("go.mod", "module example.com/cli-wire\n\ngo 1.24\n")
	mustWrite("internal/db/store.go", "package db\n\nimport \"database/sql\"\n\nfunc Insert(d *sql.DB) error { _, err := d.Exec(\"SELECT 1\"); return err }\n")
	mustWrite("internal/controllers/orders.go", "package controllers\n\nimport (\n\t\"net/http\"\n\t\"example.com/cli-wire/internal/db\"\n)\n\nfunc Register(mux *http.ServeMux) {\n\tmux.HandleFunc(\"POST /orders\", func(w http.ResponseWriter, r *http.Request) { _ = db.Insert(nil) })\n}\n")
	mustWrite("internal/leaky/fetch.go", "package leaky\n\nimport \"net/http\"\n\nfunc Ping(u string) error {\n\tresp, err := http.Get(u)\n\tif err != nil { return err }\n\t_ = resp.StatusCode\n\treturn nil\n}\n")

	m := types.BoilerplateManifest{
		Name:     "cli-wire",
		Language: types.LangGo,
		Capabilities: types.ManifestCapabilities{
			Health: types.EndpointSpec{Method: "GET", Path: "/health"},
			Diagnostics: &types.DiagnosticsCapability{
				Enabled:         true,
				PprofBaseURL:    "/debug/pprof",
				RuntimeStatsURL: "/debug/stats",
				GCTriggerURL:    "/debug/gc",
			},
		},
		Architecture: &types.ArchitectureRules{
			Layers: []types.LayerDefinition{
				{Name: "controller", PathPrefixes: []string{"internal/controllers/"}},
				{Name: "db", PathPrefixes: []string{"internal/db/"}},
			},
			ForbiddenFlows: []types.LayerFlowRule{
				{From: "controller", To: "db", Reason: "controllers must not import db directly"},
			},
			RequireAuthOnNonPublic: true,
		},
	}

	resolvedDiag := resolveDiagnosticsCapability("http://127.0.0.1:8080", m.Capabilities.Diagnostics)
	if resolvedDiag == nil || resolvedDiag.PprofBaseURL != "http://127.0.0.1:8080/debug/pprof" || resolvedDiag.GCTriggerURL != "http://127.0.0.1:8080/debug/gc" {
		t.Fatalf("unexpected resolved diagnostics config: %+v", resolvedDiag)
	}

	if !shouldMonitorEgress([]string{"pentest"}, 123, "") {
		t.Fatalf("expected egress monitor enabled during pentest with pid")
	}
	if !shouldMonitorEgress([]string{"load"}, 0, "app-ctr") {
		t.Fatalf("expected egress monitor enabled during load with container")
	}
	if shouldMonitorEgress([]string{"supplychain", "leak-sast"}, 123, "") {
		t.Fatalf("did not expect egress monitor enabled for static-only stages")
	}

	card := types.ConformanceScorecard{TargetName: m.Name, Language: m.Language}
	var stageErrs []string
	runGraphAndArchitectureStage(context.Background(), repo, m, "", parseStages("source-graph,leak-sast"), runner.ModeLocal, false, &card, &stageErrs)

	if len(stageErrs) != 0 {
		t.Fatalf("unexpected stage errors: %v", stageErrs)
	}
	if len(card.SourceGraph.LayerViolations) == 0 {
		t.Fatalf("expected LayerViolations from AnalyzeArchitectureAndRouteFlows, got none")
	}
	if len(card.SourceGraph.RouteFindings) == 0 {
		t.Fatalf("expected RouteFindings from AnalyzeArchitectureAndRouteFlows, got none")
	}
	if !slices.ContainsFunc(card.Findings, func(f types.SecurityFinding) bool { return f.ID == "leak-go-unclosed-resp-body" }) {
		t.Fatalf("expected leak-sast finding leak-go-unclosed-resp-body in %+v", card.Findings)
	}
}

func TestLoadOpenAPIDoc_ContainmentAndSizeLimit(t *testing.T) {
	parentDir := t.TempDir()
	targetDir := filepath.Join(parentDir, "repo")
	if err := os.MkdirAll(filepath.Join(targetDir, "specs"), 0o755); err != nil {
		t.Fatal(err)
	}

	outsideFile := filepath.Join(parentDir, "outside.json")
	if err := os.WriteFile(outsideFile, []byte(`{"secret":"outside-leak"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	validSpec := filepath.Join(targetDir, "specs", "openapi.json")
	wantSpec := `{"openapi":"3.0.0","paths":{"/health":{}}}`
	if err := os.WriteFile(validSpec, []byte(wantSpec), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Valid regular file inside targetDir loads cleanly.
	for _, specPath := range []string{"/specs/openapi.json", "specs/openapi.json"} {
		got := loadOpenAPIDoc(context.Background(), targetDir, "", specPath)
		if string(got) != wantSpec {
			t.Fatalf("loadOpenAPIDoc(%q) = %q, want %q", specPath, string(got), wantSpec)
		}
	}

	// 2. Traversal paths must not read outside targetDir.
	for _, escapePath := range []string{"/../../../etc/passwd", "../outside.json", "/../outside.json", "specs/../../outside.json"} {
		if got := loadOpenAPIDoc(context.Background(), targetDir, "", escapePath); len(got) != 0 {
			t.Fatalf("expected traversal path %q to be rejected, got %q", escapePath, string(got))
		}
	}

	// 3. Symlink inside targetDir escaping to outsideFile must be rejected.
	escapeLink := filepath.Join(targetDir, "escape-link.json")
	if err := os.Symlink(outsideFile, escapeLink); err != nil {
		t.Skipf("symlink not supported in test environment: %v", err)
	}
	if got := loadOpenAPIDoc(context.Background(), targetDir, "", "escape-link.json"); len(got) != 0 {
		t.Fatalf("expected escaping symlink to be rejected, got %q", string(got))
	}

	// Standard fallback candidate symlink escaping targetDir must also be rejected.
	fallbackLink := filepath.Join(targetDir, "openapi.json")
	if err := os.Symlink(outsideFile, fallbackLink); err != nil {
		t.Skipf("symlink not supported in test environment: %v", err)
	}
	if got := loadOpenAPIDoc(context.Background(), targetDir, "", ""); len(got) != 0 {
		t.Fatalf("expected escaping fallback symlink openapi.json to be rejected, got %q", string(got))
	}
	_ = os.Remove(fallbackLink)

	// 4. Oversized regular file inside targetDir is bounded to 2 MiB.
	hugeFile := filepath.Join(targetDir, "specs", "huge.json")
	hugeData := make([]byte, 2*1024*1024+4096)
	for i := range hugeData {
		hugeData[i] = 'a'
	}
	if err := os.WriteFile(hugeFile, hugeData, 0o644); err != nil {
		t.Fatal(err)
	}
	gotHuge := loadOpenAPIDoc(context.Background(), targetDir, "", "/specs/huge.json")
	if len(gotHuge) != 2*1024*1024 {
		t.Fatalf("expected oversized local OpenAPI read bounded to %d bytes, got %d", 2*1024*1024, len(gotHuge))
	}
}
