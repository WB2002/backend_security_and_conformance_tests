package report_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/policy"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/report"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestReportBundleGeneration(t *testing.T) {
	card := types.ConformanceScorecard{
		TargetName: "elixir-boilerplate",
		Language:   types.LangElixir,
		Timestamp:  "2026-11-23T23:00:00Z",
		Findings: []types.SecurityFinding{
			{
				ID:          "semgrep-1",
				Category:    types.CategorySAST,
				Tool:        "semgrep",
				Severity:    types.SeverityHigh,
				Title:       `Unsafe Atom Conversion <script>alert("xss")</script>`,
				Description: "String.to_atom on user input",
				FilePath:    "lib/app/auth.ex",
				Line:        33,
				CWE:         "CWE-400",
			},
		},
		SourceGraph: types.DependencyGraph{
			Nodes: []types.GraphNode{
				{ID: "lib/app/auth.ex", Label: "lib/app/auth.ex", Type: "module", Sinks: []string{"auth"}},
				{ID: "lib/app/users.ex", Label: "lib/app/users.ex [evil](x)", Type: "module", Sinks: []string{"db"}},
			},
			Edges: []types.GraphEdge{
				{From: "lib/app/auth.ex", To: "lib/app/users.ex", Kind: "import"},
				{From: "lib/app/users.ex", To: "lib/app/auth.ex", Kind: "import"},
			},
			Cycles: []types.CycleFinding{
				{
					ID:              "cycle-1",
					GraphType:       "source",
					Nodes:           []string{"lib/app/auth.ex", "lib/app/users.ex", "lib/app/auth.ex"},
					IsToxic:         true,
					Severity:        types.SeverityCritical,
					Reasons:         []string{"Contains SAST high finding"},
					RelatedFindings: []string{"semgrep-1"},
				},
			},
		},
	}

	mmd := report.GenerateMermaidDependencyGraph(card)
	if !strings.Contains(mmd, "flowchart LR") || !strings.Contains(mmd, "toxicCycle") {
		t.Fatalf("unexpected mermaid output:\n%s", mmd)
	}
	if strings.Contains(mmd, "[evil](x)") {
		t.Fatalf("expected Mermaid label injection `[evil](x)` to be escaped, got:\n%s", mmd)
	}

	sarifBytes, err := report.GenerateSARIFReport(card)
	if err != nil {
		t.Fatalf("sarif error: %v", err)
	}
	var sarifDoc map[string]any
	if err := json.Unmarshal(sarifBytes, &sarifDoc); err != nil || sarifDoc["version"] != "2.1.0" {
		t.Fatalf("invalid sarif 2.1.0 doc: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "conformance-reports-*")
	if err != nil {
		t.Fatalf("mkdtemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	polRes := policy.EvaluateSecurityPolicy(card, policy.StrictSecurityPolicy())
	paths, err := report.WriteReportBundle(tmpDir, card, polRes)
	if err != nil {
		t.Fatalf("WriteReportBundle failed: %v", err)
	}

	htmlBytes, err := os.ReadFile(paths.HTMLPath)
	if err != nil {
		t.Fatalf("failed to read html dashboard: %v", err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "elixir-boilerplate") || !strings.Contains(htmlStr, "Toxic Cycle") {
		t.Fatalf("expected target name and Toxic Cycle badge in HTML")
	}
	if strings.Contains(htmlStr, `<script>alert("xss")</script>`) || !strings.Contains(htmlStr, "&lt;script&gt;") {
		t.Fatalf("expected HTML escaping of finding title in dashboard.html")
	}
	if !strings.Contains(htmlStr, "cytoscape") {
		t.Fatalf("expected interactive Cytoscape graph viewer in dashboard.html")
	}
	if !strings.Contains(htmlStr, "Content-Security-Policy") {
		t.Fatalf("expected Content-Security-Policy meta tag in dashboard.html")
	}
	const expectedSRI = "sha384-J7Q85oZE4GJ/e7+n2aOQsLXfDwwfnA8S2nZAL5BpFsfpCF84zQD7LroZ/dMnLgex"
	if !strings.Contains(htmlStr, expectedSRI) || !strings.Contains(htmlStr, `crossorigin="anonymous"`) {
		t.Fatalf("expected Cytoscape SRI integrity %q and crossorigin=\"anonymous\" in dashboard.html", expectedSRI)
	}

	if paths.ChecksumPath == "" {
		t.Fatalf("expected ChecksumPath to be populated")
	}
	checksumBytes, err := os.ReadFile(paths.ChecksumPath)
	if err != nil {
		t.Fatalf("failed to read scorecard.sha256: %v", err)
	}
	scorecardBytes, err := os.ReadFile(paths.ScorecardPath)
	if err != nil {
		t.Fatalf("failed to read scorecard.json: %v", err)
	}
	expectedSum := sha256.Sum256(scorecardBytes)
	expectedHex := hex.EncodeToString(expectedSum[:])
	if len(expectedHex) != 64 || !strings.Contains(string(checksumBytes), expectedHex+"  scorecard.json") {
		t.Fatalf("expected 64-hex SHA-256 digest %q in scorecard.sha256, got %q", expectedHex, string(checksumBytes))
	}

	// Empty findings SARIF must have "results": [] (not null)
	emptySarif, err := report.GenerateSARIFReport(types.ConformanceScorecard{TargetName: "clean"})
	if err != nil || strings.Contains(string(emptySarif), `"results": null`) {
		t.Fatalf("expected non-null empty results array in SARIF: %s", string(emptySarif))
	}
}

func TestReportSARIFCodeFlowsAndDashboardEnrichments(t *testing.T) {
	reachableTrue := true
	card := types.ConformanceScorecard{
		TargetName: "payments-api",
		Language:   types.LangTypeScript,
		Findings: []types.SecurityFinding{
			{
				ID:          "osv-body-parser-CVE-2021-44228",
				Category:    types.CategorySCA,
				Tool:        "osv-scanner",
				Severity:    types.SeverityCritical,
				Title:       "CVE-2021-44228 in body-parser@1.20.0",
				CVE:         "CVE-2021-44228",
				PackageName: "body-parser",
				Reachable:   &reachableTrue,
				KEV:         true,
				EPSS:        0.975,
			},
			{
				ID:       "route-sink-1",
				Category: types.CategoryArchitecture,
				Tool:     "route-flow-analyzer",
				Severity: types.SeverityHigh,
				Title:    "Unvalidated route reaches db sink",
				FilePath: "src/controllers/order.controller.ts",
				Line:     5,
				CodeFlows: [][]types.CodeFlowStep{
					{
						{FilePath: "src/controllers/order.controller.ts", Line: 5, Message: "POST /orders entry", Kind: "source"},
						{FilePath: "src/db/prisma.ts", Line: 1, Message: "Reaches db sink", Kind: "sink"},
					},
				},
			},
		},
		SourceGraph: types.DependencyGraph{
			LayerViolations: []types.LayerViolation{
				{
					ID:        "layer-violation-1",
					FromFile:  "src/controllers/order.controller.ts",
					ToFile:    "src/db/prisma.ts",
					FromLayer: "controller",
					ToLayer:   "db",
					Reason:    "No direct DB access from controller",
					Severity:  types.SeverityHigh,
				},
			},
			RouteFindings: []types.RouteGuardFinding{
				{
					ID:            "route-guard-1",
					Method:        "POST",
					Path:          "/orders",
					FilePath:      "src/controllers/order.controller.ts",
					Line:          5,
					Kind:          "unprotected-route",
					MissingGuards: []string{"auth"},
					Severity:      types.SeverityHigh,
				},
			},
		},
	}

	sarifBytes, err := report.GenerateSARIFReport(card)
	if err != nil {
		t.Fatalf("GenerateSARIFReport failed: %v", err)
	}
	if !strings.Contains(string(sarifBytes), `"codeFlows"`) || !strings.Contains(string(sarifBytes), `"threadFlows"`) {
		t.Fatalf("expected SARIF codeFlows and threadFlows, got:\n%s", string(sarifBytes))
	}

	htmlStr := report.GenerateHTMLDashboard(card, policy.EvaluateSecurityPolicy(card, policy.StrictSecurityPolicy()))
	for _, want := range []string{"KEV", "Reachable", "Layer Violations", "controller", "Route Guard", "unprotected-route", "/orders"} {
		if !strings.Contains(htmlStr, want) {
			t.Fatalf("expected dashboard HTML to contain %q", want)
		}
	}
}


