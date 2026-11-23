package report_test

import (
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
				{ID: "lib/app/users.ex", Label: "lib/app/users.ex", Type: "module", Sinks: []string{"db"}},
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
}
