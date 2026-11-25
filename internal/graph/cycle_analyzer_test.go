package graph_test

import (
	"slices"
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

func TestFilterPeerDependencyEdgesEliminatesPeerCyclesButKeepsHardCycles(t *testing.T) {
	pnpmLock := []byte(`lockfileVersion: '9.0'
packages:
  '@eslint-community/eslint-utils@4.9.1':
    resolution: {integrity: sha512-abc}
    peerDependencies:
      eslint: ^6.0.0 || ^7.0.0 || >=8.0.0

  pg-pool@3.11.0:
    resolution: {integrity: sha512-def}
    peerDependencies:
      pg: '>=8.0'

  pkg-a@1.0.0:
    resolution: {integrity: sha512-ghi}

  pkg-b@2.0.0:
    resolution: {integrity: sha512-jkl}
`)

	peerDeps := graph.ParsePnpmLockPeerDependencies(pnpmLock)
	if !peerDeps["pg-pool@3.11.0"]["pg"] {
		t.Fatalf("expected pg-pool@3.11.0 to have peerDependency pg, got %+v", peerDeps)
	}
	if !peerDeps["@eslint-community/eslint-utils@4.9.1"]["eslint"] {
		t.Fatalf("expected @eslint-community/eslint-utils@4.9.1 to have peerDependency eslint, got %+v", peerDeps)
	}

	cdx := []byte(`{
  "components": [
    { "bom-ref": "pkg:npm/pg@8.18.0", "name": "pg", "version": "8.18.0" },
    { "bom-ref": "pkg:npm/pg-pool@3.11.0", "name": "pg-pool", "version": "3.11.0" },
    { "bom-ref": "pkg:npm/%40eslint-community/eslint-utils@4.9.1", "name": "@eslint-community/eslint-utils", "version": "4.9.1" },
    { "bom-ref": "pkg:npm/eslint@9.39.2", "name": "eslint", "version": "9.39.2" },
    { "bom-ref": "pkg:npm/pkg-a@1.0.0", "name": "pkg-a", "version": "1.0.0" },
    { "bom-ref": "pkg:npm/pkg-b@2.0.0", "name": "pkg-b", "version": "2.0.0" }
  ],
  "dependencies": [
    { "ref": "pkg:npm/pg@8.18.0", "dependsOn": ["pkg:npm/pg-pool@3.11.0"] },
    { "ref": "pkg:npm/pg-pool@3.11.0", "dependsOn": ["pkg:npm/pg@8.18.0"] },
    { "ref": "pkg:npm/eslint@9.39.2", "dependsOn": ["pkg:npm/%40eslint-community/eslint-utils@4.9.1"] },
    { "ref": "pkg:npm/%40eslint-community/eslint-utils@4.9.1", "dependsOn": ["pkg:npm/eslint@9.39.2"] },
    { "ref": "pkg:npm/pkg-a@1.0.0", "dependsOn": ["pkg:npm/pkg-b@2.0.0"] },
    { "ref": "pkg:npm/pkg-b@2.0.0", "dependsOn": ["pkg:npm/pkg-a@1.0.0"] }
  ]
}`)

	sbomG, _, err := graph.ParseCycloneDXSBOMGraph(cdx, nil)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	filtered := graph.FilterPeerDependencyEdges(sbomG, peerDeps)
	cycles := graph.FindGraphCycles(filtered, "package", nil)
	if len(cycles) != 1 {
		t.Fatalf("expected exactly 1 real cycle (pkg-a <-> pkg-b), got %d: %+v", len(cycles), cycles)
	}
	if cycles[0].Nodes[0] != "pkg:npm/pkg-a@1.0.0" || cycles[0].Nodes[1] != "pkg:npm/pkg-b@2.0.0" {
		t.Fatalf("unexpected remaining cycle: %+v", cycles[0])
	}
}

func TestParseCycloneDXSBOMGraphUpgradesOSVMalwareToCriticalMalwareCategory(t *testing.T) {
	cdx := []byte(`{
  "components": [
    { "bom-ref": "pkg:npm/evil-pkg@1.0.0", "name": "evil-pkg", "version": "1.0.0" }
  ],
  "dependencies": []
}`)
	osv := []byte(`{
  "results": [
    {
      "packages": [
        {
          "package": { "name": "evil-pkg", "version": "1.0.0", "ecosystem": "npm" },
          "vulnerabilities": [
            {
              "id": "MAL-2026-9999",
              "summary": "Malicious package exfiltrating env vars",
              "database_specific": { "severity": "" }
            }
          ]
        }
      ]
    }
  ]
}`)

	_, findings, err := graph.ParseCycloneDXSBOMGraph(cdx, osv)
	if err != nil {
		t.Fatalf("ParseCycloneDXSBOMGraph failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Category != types.CategoryMalware {
		t.Fatalf("expected Category %q, got %q", types.CategoryMalware, findings[0].Category)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Fatalf("expected Severity %q, got %q", types.SeverityCritical, findings[0].Severity)
	}

	// 2-node SBOM cycle containing a MAL-* package must be flagged as a Critical toxic cycle.
	cdxCycle := []byte(`{
  "components": [
    { "bom-ref": "pkg:npm/evil-pkg@1.0.0", "name": "evil-pkg", "version": "1.0.0" },
    { "bom-ref": "pkg:npm/helper-pkg@1.0.0", "name": "helper-pkg", "version": "1.0.0" }
  ],
  "dependencies": [
    { "ref": "pkg:npm/evil-pkg@1.0.0", "dependsOn": ["pkg:npm/helper-pkg@1.0.0"] },
    { "ref": "pkg:npm/helper-pkg@1.0.0", "dependsOn": ["pkg:npm/evil-pkg@1.0.0"] }
  ]
}`)
	sbomCycleG, cycleFindings, err := graph.ParseCycloneDXSBOMGraph(cdxCycle, osv)
	if err != nil {
		t.Fatalf("ParseCycloneDXSBOMGraph cycle failed: %v", err)
	}
	if len(cycleFindings) != 1 {
		t.Fatalf("expected 1 malware finding on cycle graph, got %d: %+v", len(cycleFindings), cycleFindings)
	}
	_, analyzedSBOM := graph.AnalyzeDependencyGraphs(types.DependencyGraph{}, sbomCycleG, cycleFindings)
	if len(analyzedSBOM.Cycles) != 1 {
		t.Fatalf("expected 1 cycle in 2-node MAL-* SBOM graph, got %d: %+v", len(analyzedSBOM.Cycles), analyzedSBOM.Cycles)
	}
	cyc := analyzedSBOM.Cycles[0]
	if !cyc.IsToxic || cyc.Severity != types.SeverityCritical {
		t.Fatalf("expected Critical toxic cycle for MAL-* package, got %+v", cyc)
	}
	if !slices.Contains(cyc.RelatedFindings, cycleFindings[0].ID) {
		t.Fatalf("expected RelatedFindings to contain %q, got %+v", cycleFindings[0].ID, cyc.RelatedFindings)
	}
}

