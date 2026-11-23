package graph_test

import (
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/graph"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestTarjanCycleDetectorAndSBOMOverlay(t *testing.T) {
	srcGraph := types.DependencyGraph{
		Nodes: []types.GraphNode{
			{ID: "src/auth.ts", Label: "src/auth.ts", Type: "module", Sinks: []string{"auth"}},
			{ID: "src/users.ts", Label: "src/users.ts", Type: "module", Sinks: []string{"db"}},
			{ID: "src/billing.ts", Label: "src/billing.ts", Type: "module"},
			{ID: "src/utils.ts", Label: "src/utils.ts", Type: "module"},
		},
		Edges: []types.GraphEdge{
			{From: "src/auth.ts", To: "src/users.ts", Kind: "import"},
			{From: "src/users.ts", To: "src/billing.ts", Kind: "import"},
			{From: "src/billing.ts", To: "src/auth.ts", Kind: "import"},
			{From: "src/billing.ts", To: "src/utils.ts", Kind: "import"},
		},
	}
	findings := []types.SecurityFinding{
		{
			ID:       "sast-sqli",
			Category: types.CategorySAST,
			Tool:     "semgrep",
			Severity: types.SeverityHigh,
			Title:    "SQL Injection in users query",
			FilePath: "src/users.ts",
			Line:     28,
		},
	}

	cycles := graph.FindGraphCycles(srcGraph, "source", findings)
	if len(cycles) != 1 {
		t.Fatalf("expected 1 cycle, got %d: %+v", len(cycles), cycles)
	}
	if !cycles[0].IsToxic || cycles[0].Severity != types.SeverityCritical {
		t.Fatalf("expected critical toxic cycle, got %+v", cycles[0])
	}
	if len(cycles[0].RelatedFindings) != 1 || cycles[0].RelatedFindings[0] != "sast-sqli" {
		t.Fatalf("expected related finding sast-sqli, got %+v", cycles[0].RelatedFindings)
	}

	cdx := []byte(`{
  "components": [
    { "bom-ref": "pkg:npm/pkg-a@1.0.0", "name": "pkg-a", "version": "1.0.0" },
    { "bom-ref": "pkg:npm/pkg-b@2.0.0", "name": "pkg-b", "version": "2.0.0" }
  ],
  "dependencies": [
    { "ref": "pkg:npm/pkg-a@1.0.0", "dependsOn": ["pkg:npm/pkg-b@2.0.0"] },
    { "ref": "pkg:npm/pkg-b@2.0.0", "dependsOn": ["pkg:npm/pkg-a@1.0.0"] }
  ]
}`)
	osv := []byte(`{
  "results": [
    {
      "packages": [
        {
          "package": { "name": "pkg-b", "version": "2.0.0", "ecosystem": "npm" },
          "vulnerabilities": [
            {
              "id": "GHSA-xxxx-yyyy",
              "summary": "Remote code execution in pkg-b",
              "database_specific": { "severity": "CRITICAL" }
            }
          ]
        }
      ]
    }
  ]
}`)

	sbomG, scaFindings, err := graph.ParseCycloneDXSBOMGraph(cdx, osv)
	if err != nil || len(scaFindings) != 1 {
		t.Fatalf("sbom parse failed: err=%v findings=%+v", err, scaFindings)
	}
	_, analyzedSBOM := graph.AnalyzeDependencyGraphs(types.DependencyGraph{}, sbomG, scaFindings)
	if len(analyzedSBOM.Cycles) != 1 || !analyzedSBOM.Cycles[0].IsToxic {
		t.Fatalf("expected toxic SBOM package cycle, got %+v", analyzedSBOM.Cycles)
	}

	// Verify long cycle (>= 13 nodes) is still detected via fallback
	var longNodes []types.GraphNode
	var longEdges []types.GraphEdge
	for i := 0; i < 14; i++ {
		id := "n" + string(rune('a'+i))
		next := "n" + string(rune('a'+((i+1)%14)))
		longNodes = append(longNodes, types.GraphNode{ID: id, Label: id, Type: "module"})
		longEdges = append(longEdges, types.GraphEdge{From: id, To: next, Kind: "import"})
	}
	longCycles := graph.FindGraphCycles(types.DependencyGraph{Nodes: longNodes, Edges: longEdges}, "source", nil)
	if len(longCycles) == 0 {
		t.Fatalf("expected cycle of length 14 to be detected, got 0 cycles")
	}
}

