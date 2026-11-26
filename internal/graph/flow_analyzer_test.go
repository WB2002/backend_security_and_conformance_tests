package graph_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/graph"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/report"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestLinkSourceToPackageReachabilityAndOSVCVSS(t *testing.T) {
	sev, ok := graph.ParseCVSSSeverity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
	if !ok || sev != types.SeverityMedium {
		t.Fatalf("expected CVSS 3.1 vector to map to SeverityMedium, got sev=%q ok=%v", sev, ok)
	}

	cdx := []byte(`{
  "components": [
    { "bom-ref": "pkg:npm/express@4.18.2", "name": "express", "version": "4.18.2" },
    { "bom-ref": "pkg:npm/body-parser@1.20.0", "name": "body-parser", "version": "1.20.0" },
    { "bom-ref": "pkg:npm/unused-dev-pkg@0.1.0", "name": "unused-dev-pkg", "version": "0.1.0" }
  ],
  "dependencies": [
    { "ref": "pkg:npm/express@4.18.2", "dependsOn": ["pkg:npm/body-parser@1.20.0"] }
  ]
}`)
	osv := []byte(`{
  "results": [
    {
      "packages": [
        {
          "package": { "name": "body-parser", "version": "1.20.0", "ecosystem": "npm" },
          "vulnerabilities": [
            {
              "id": "CVE-2021-44228",
              "summary": "KEV-listed critical vulnerability",
              "severity": [
                { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }
              ]
            }
          ]
        },
        {
          "package": { "name": "unused-dev-pkg", "version": "0.1.0", "ecosystem": "npm" },
          "vulnerabilities": [
            {
              "id": "GHSA-0000-1111-2222",
              "summary": "Medium vulnerability in unused package",
              "severity": [
                { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }
              ]
            }
          ]
        }
      ]
    }
  ]
}`)

	pkgGraph, findings, err := graph.ParseCycloneDXSBOMGraph(cdx, osv)
	if err != nil {
		t.Fatalf("ParseCycloneDXSBOMGraph failed: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}

	srcGraph := types.DependencyGraph{
		Nodes: []types.GraphNode{
			{
				ID:              "src/controllers/order.controller.ts",
				Label:           "src/controllers/order.controller.ts",
				Type:            "module",
				ExternalImports: []string{"express"},
			},
		},
	}

	linkedSrc, _, enriched := graph.LinkSourceToPackageReachability(srcGraph, pkgGraph, findings)

	var foundExtEdge bool
	for _, e := range linkedSrc.Edges {
		if e.From == "src/controllers/order.controller.ts" && e.To == "pkg:npm/express@4.18.2" && e.Kind == "external-import" {
			foundExtEdge = true
		}
	}
	if !foundExtEdge {
		t.Fatalf("expected external-import edge to pkg:npm/express@4.18.2, got %+v", linkedSrc.Edges)
	}

	byPkg := make(map[string]types.SecurityFinding)
	for _, f := range enriched {
		byPkg[f.PackageName] = f
	}

	bp := byPkg["body-parser"]
	if !bp.KEV || bp.Severity != types.SeverityCritical {
		t.Fatalf("expected KEV CVE on body-parser to escalate to SeverityCritical with KEV=true, got %+v", bp)
	}
	if bp.Reachable == nil || !*bp.Reachable {
		t.Fatalf("expected body-parser (transitive via imported express) to be Reachable=true, got %+v", bp)
	}

	unused := byPkg["unused-dev-pkg"]
	if unused.Severity != types.SeverityMedium {
		t.Fatalf("expected unused-dev-pkg CVSS 3.1 vector to map to SeverityMedium, got %+v", unused)
	}
	if unused.Reachable == nil || *unused.Reachable {
		t.Fatalf("expected unused-dev-pkg to be Reachable=false, got %+v", unused)
	}
}

func TestAnalyzeArchitectureAndRouteFlows_ForbiddenLayerUnprotectedAndShadowRoutes(t *testing.T) {
	files := map[string]string{
		"src/controllers/order.controller.ts": `
import { prisma } from '../db/prisma';
import express from 'express';
const router = express.Router();
router.post('/orders', async (req, res) => {
  res.json(await prisma.order.create(req.body));
});
router.delete('/debug/drop', async (req, res) => {
  res.json(await prisma.rawDrop());
});
export default router;
`,
		"src/db/prisma.ts": `
export const prisma = {
  order: { create: async (x: any) => x },
  rawDrop: async () => true,
};
`,
	}

	srcGraph := graph.BuildSourceGraphFromFiles(files, graph.SourceGraphOptions{
		Language: types.LangTypeScript,
	})

	arch := &types.ArchitectureRules{
		Layers: []types.LayerDefinition{
			{Name: "controller", PathPrefixes: []string{"src/controllers/"}},
			{Name: "db", PathPrefixes: []string{"src/db/"}},
		},
		ForbiddenFlows: []types.LayerFlowRule{
			{From: "controller", To: "db", Reason: "Controllers must call services, not DB directly"},
		},
		PublicRoutes:           []string{"/health"},
		RequireAuthOnNonPublic: true,
	}

	openAPI := []byte(`{
  "openapi": "3.0.0",
  "paths": {
    "/orders": { "post": {} },
    "/health": { "get": {} }
  }
}`)

	analyzedGraph, findings := graph.AnalyzeArchitectureAndRouteFlows("", files, srcGraph, arch, openAPI)

	if len(analyzedGraph.LayerViolations) == 0 {
		t.Fatalf("expected LayerViolation for controller -> db, got none")
	}
	if analyzedGraph.LayerViolations[0].FromLayer != "controller" || analyzedGraph.LayerViolations[0].ToLayer != "db" {
		t.Fatalf("unexpected layer violation: %+v", analyzedGraph.LayerViolations[0])
	}

	var foundUnprotected, foundShadow bool
	for _, rf := range analyzedGraph.RouteFindings {
		if rf.Kind == "unprotected-route" && rf.Method == "POST" && rf.Path == "/orders" {
			foundUnprotected = true
		}
		if rf.Kind == "shadow-route" && rf.Method == "DELETE" && rf.Path == "/debug/drop" {
			foundShadow = true
		}
	}
	if !foundUnprotected {
		t.Fatalf("expected unprotected-route finding for POST /orders, got %+v", analyzedGraph.RouteFindings)
	}
	if !foundShadow {
		t.Fatalf("expected shadow-route finding for DELETE /debug/drop, got %+v", analyzedGraph.RouteFindings)
	}

	var hasCodeFlow bool
	for _, f := range findings {
		if len(f.CodeFlows) > 0 && len(f.CodeFlows[0]) >= 2 {
			hasCodeFlow = true
		}
	}
	if !hasCodeFlow {
		t.Fatalf("expected Route -> Sink CodeFlows in findings, got %+v", findings)
	}

	sarifBytes, err := report.GenerateSARIFReport(types.ConformanceScorecard{
		TargetName:  "order-api",
		Language:    types.LangTypeScript,
		Findings:    findings,
		SourceGraph: analyzedGraph,
	})
	if err != nil {
		t.Fatalf("GenerateSARIFReport failed: %v", err)
	}

	var sarifDoc struct {
		Runs []struct {
			Results []struct {
				CodeFlows []struct {
					ThreadFlows []struct {
						Locations []map[string]any `json:"locations"`
					} `json:"threadFlows"`
				} `json:"codeFlows"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarifBytes, &sarifDoc); err != nil {
		t.Fatalf("unmarshal SARIF failed: %v", err)
	}
	var sarifHasFlow bool
	for _, run := range sarifDoc.Runs {
		for _, res := range run.Results {
			if len(res.CodeFlows) > 0 && len(res.CodeFlows[0].ThreadFlows) > 0 && len(res.CodeFlows[0].ThreadFlows[0].Locations) >= 2 {
				sarifHasFlow = true
			}
		}
	}
	if !sarifHasFlow {
		t.Fatalf("expected SARIF codeFlows[0].threadFlows[0].locations, got:\n%s", string(sarifBytes))
	}
}

func TestPolyglotRouteExtractionAndOfflineEPSSNoOp(t *testing.T) {
	files := map[string]string{
		"internal/http/router.go": `
package http
import "github.com/go-chi/chi/v5"
func Routes(r chi.Router) {
	r.Post("/payments", createPayment)
}
`,
		"app/routes.py": `
@router.post("/invoices")
def create_invoice():
    pass
`,
		"lib/my_app_web/router.ex": `
defmodule MyAppWeb.Router do
  use Phoenix.Router
  scope "/api" do
    delete "/sessions", SessionController, :delete
  end
end
`,
	}

	g, _ := graph.AnalyzeArchitectureAndRouteFlows("", files, types.DependencyGraph{}, nil, nil)
	want := map[string]bool{
		"POST /payments":       false,
		"POST /invoices":       false,
		"DELETE /api/sessions": false,
	}
	for _, rf := range g.RouteFindings {
		key := rf.Method + " " + rf.Path
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("expected polyglot route finding for %q, got %+v", k, g.RouteFindings)
		}
	}

	// Verify EPSS enrichment with onlineEnrich=false is a clean offline no-op
	in := []types.SecurityFinding{{ID: "f1", CVE: "CVE-2021-44228"}}
	out := graph.EnrichFindingsWithEPSS(context.Background(), in, false)
	if len(out) != 1 || out[0].EPSS != 0 {
		t.Fatalf("expected offline EPSS enrichment to leave EPSS=0, got %+v", out)
	}
}

