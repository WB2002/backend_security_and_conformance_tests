package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

type ReportBundlePaths struct {
	ScorecardPath string
	SARIFPath     string
	MermaidPath   string
	HTMLPath      string
}

func sanitizeMermaidID(raw string) string {
	var b strings.Builder
	b.WriteString("n_")
	var h uint32 = 2166136261
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		h ^= uint32(ch)
		h *= 16777619
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			b.WriteByte(ch)
		} else {
			b.WriteByte('_')
		}
	}
	b.WriteString(fmt.Sprintf("_%04x", h&0xffff))
	return b.String()
}

func escapeMermaidLabel(raw string) string {
	s := strings.ReplaceAll(raw, `"`, `'`)
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func GenerateMermaidDependencyGraph(card types.ConformanceScorecard) string {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	b.WriteString("  classDef toxicCycle fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#b71c1c;\n")
	b.WriteString("  classDef cycleNode fill:#fff8e1,stroke:#f57f17,stroke-width:2px;\n")

	toxicNodes := make(map[string]bool)
	cycleNodes := make(map[string]bool)
	for _, c := range card.SourceGraph.Cycles {
		for _, n := range c.Nodes {
			cycleNodes[n] = true
			if c.IsToxic {
				toxicNodes[n] = true
			}
		}
	}
	for _, c := range card.PackageGraph.Cycles {
		for _, n := range c.Nodes {
			cycleNodes[n] = true
			if c.IsToxic {
				toxicNodes[n] = true
			}
		}
	}

	allNodes := append([]types.GraphNode{}, card.SourceGraph.Nodes...)
	allNodes = append(allNodes, card.PackageGraph.Nodes...)
	for _, n := range allNodes {
		mID := sanitizeMermaidID(n.ID)
		b.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", mID, escapeMermaidLabel(n.Label)))
		if toxicNodes[n.ID] {
			b.WriteString(fmt.Sprintf("  class %s toxicCycle;\n", mID))
		} else if cycleNodes[n.ID] {
			b.WriteString(fmt.Sprintf("  class %s cycleNode;\n", mID))
		}
	}

	allEdges := append([]types.GraphEdge{}, card.SourceGraph.Edges...)
	allEdges = append(allEdges, card.PackageGraph.Edges...)
	for _, e := range allEdges {
		fromID := sanitizeMermaidID(e.From)
		toID := sanitizeMermaidID(e.To)
		if cycleNodes[e.From] && cycleNodes[e.To] {
			b.WriteString(fmt.Sprintf("  %s == cycle ==> %s\n", fromID, toID))
		} else {
			b.WriteString(fmt.Sprintf("  %s --> %s\n", fromID, toID))
		}
	}

	return b.String()
}

func sarifLevel(sev types.Severity) string {
	switch sev {
	case types.SeverityCritical, types.SeverityHigh:
		return "error"
	case types.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func GenerateSARIFReport(card types.ConformanceScorecard) ([]byte, error) {
	results := make([]map[string]any, 0)
	for _, f := range card.Findings {
		loc := f.FilePath
		if loc == "" {
			loc = f.Endpoint
		}
		if loc == "" {
			loc = "project"
		}
		line := f.Line
		if line <= 0 {
			line = 1
		}
		results = append(results, map[string]any{
			"ruleId": f.ID,
			"level":  sarifLevel(f.Severity),
			"message": map[string]any{
				"text": fmt.Sprintf("[%s] %s: %s", f.Tool, f.Title, f.Description),
			},
			"locations": []map[string]any{
				{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{"uri": loc},
						"region":           map[string]any{"startLine": line},
					},
				},
			},
		})
	}

	for _, c := range append(append([]types.CycleFinding{}, card.SourceGraph.Cycles...), card.PackageGraph.Cycles...) {
		uri := "dependency-graph"
		if len(c.Nodes) > 0 {
			uri = c.Nodes[0]
		}
		results = append(results, map[string]any{
			"ruleId": c.ID,
			"level":  sarifLevel(c.Severity),
			"message": map[string]any{
				"text": fmt.Sprintf("Dependency cycle (%s, toxic=%v): %s", c.GraphType, c.IsToxic, strings.Join(c.Nodes, " -> ")),
			},
			"locations": []map[string]any{
				{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{"uri": uri},
						"region":           map[string]any{"startLine": 1},
					},
				},
			},
		})
	}

	for _, pt := range card.PenTestResults {
		if pt.Status != "failed" {
			continue
		}
		uri := pt.Endpoint
		if uri == "" {
			uri = "api"
		}
		results = append(results, map[string]any{
			"ruleId": pt.ID,
			"level":  sarifLevel(pt.Severity),
			"message": map[string]any{
				"text": fmt.Sprintf("[pentest] %s: %s", pt.Name, pt.Details),
			},
			"locations": []map[string]any{
				{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{"uri": uri},
						"region":           map[string]any{"startLine": 1},
					},
				},
			},
		})
	}

	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":    "conformance-audit",
						"version": "1.0.0",
					},
				},
				"results": results,
			},
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func GenerateHTMLDashboard(card types.ConformanceScorecard, policyRes types.PolicyEvaluationResult) string {
	var b strings.Builder
	statusBadge := `<span class="badge pass">PASSED</span>`
	if !policyRes.Passed {
		statusBadge = `<span class="badge fail">FAILED</span>`
	}

	toxicNodes := make(map[string]bool)
	for _, c := range append(append([]types.CycleFinding{}, card.SourceGraph.Cycles...), card.PackageGraph.Cycles...) {
		if c.IsToxic {
			for _, n := range c.Nodes {
				toxicNodes[n] = true
			}
		}
	}

	type cytoData struct {
		ID     string `json:"id"`
		Label  string `json:"label,omitempty"`
		Source string `json:"source,omitempty"`
		Target string `json:"target,omitempty"`
		Toxic  bool   `json:"toxic,omitempty"`
	}
	type cytoElem struct {
		Data cytoData `json:"data"`
	}
	var cytoElements []cytoElem
	for _, n := range append(append([]types.GraphNode{}, card.SourceGraph.Nodes...), card.PackageGraph.Nodes...) {
		cytoElements = append(cytoElements, cytoElem{
			Data: cytoData{ID: n.ID, Label: n.Label, Toxic: toxicNodes[n.ID]},
		})
	}
	for i, e := range append(append([]types.GraphEdge{}, card.SourceGraph.Edges...), card.PackageGraph.Edges...) {
		cytoElements = append(cytoElements, cytoElem{
			Data: cytoData{ID: fmt.Sprintf("e-%d", i+1), Source: e.From, Target: e.To},
		})
	}
	cytoJSON, _ := json.Marshal(cytoElements)

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Conformance Audit Dashboard — ` + html.EscapeString(card.TargetName) + `</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; margin: 24px; background: #0f172a; color: #f8fafc; }
  h1, h2 { color: #e2e8f0; }
  .badge { padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 12px; }
  .pass { background: #166534; color: #dcfce7; }
  .fail { background: #991b1b; color: #fee2e2; }
  .toxic { background: #7f1d1d; color: #fecaca; border: 1px solid #ef4444; }
  #cy { width: 100%; height: 420px; background: #1e293b; border-radius: 8px; margin-bottom: 24px; border: 1px solid #334155; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 24px; background: #1e293b; border-radius: 8px; overflow: hidden; }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #334155; }
  th { background: #334155; color: #cbd5e1; }
  pre { background: #1e293b; padding: 16px; border-radius: 8px; overflow-x: auto; }
</style>
</head>
<body>
`)
	b.WriteString(fmt.Sprintf("<h1>Polyglot Security &amp; Conformance Dashboard: %s (%s) %s</h1>\n",
		html.EscapeString(card.TargetName),
		html.EscapeString(string(card.Language)),
		statusBadge,
	))

	if len(policyRes.Violations) > 0 {
		b.WriteString("<h2>Policy Gate Violations</h2><ul>\n")
		for _, v := range policyRes.Violations {
			b.WriteString("<li>" + html.EscapeString(v) + "</li>\n")
		}
		b.WriteString("</ul>\n")
	}

	b.WriteString("<h2>Interactive Cytoscape Dependency &amp; Vulnerability Graph</h2>\n")
	b.WriteString("<div id=\"cy\"></div>\n")

	allCycles := append([]types.CycleFinding{}, card.SourceGraph.Cycles...)
	allCycles = append(allCycles, card.PackageGraph.Cycles...)
	b.WriteString("<h2>Dependency Cycles &amp; Toxic Cycle Analysis</h2>\n")
	b.WriteString("<table><thead><tr><th>ID</th><th>Graph</th><th>Toxicity</th><th>Severity</th><th>Cycle Path</th><th>Reasons</th></tr></thead><tbody>\n")
	for _, c := range allCycles {
		toxBadge := `<span class="badge">Architectural Cycle</span>`
		if c.IsToxic {
			toxBadge = `<span class="badge toxic">Toxic Cycle</span>`
		}
		b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(c.ID),
			html.EscapeString(c.GraphType),
			toxBadge,
			html.EscapeString(string(c.Severity)),
			html.EscapeString(strings.Join(c.Nodes, " → ")),
			html.EscapeString(strings.Join(c.Reasons, "; ")),
		))
	}
	b.WriteString("</tbody></table>\n")

	b.WriteString("<h2>Security Findings (SAST, Secrets, IaC, SCA, DAST)</h2>\n")
	b.WriteString("<table><thead><tr><th>ID</th><th>Tool</th><th>Category</th><th>Severity</th><th>Title</th><th>Location</th></tr></thead><tbody>\n")
	for _, f := range card.Findings {
		loc := f.FilePath
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.FilePath, f.Line)
		} else if loc == "" {
			loc = f.Endpoint
		}
		b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(f.ID),
			html.EscapeString(f.Tool),
			html.EscapeString(string(f.Category)),
			html.EscapeString(string(f.Severity)),
			html.EscapeString(f.Title),
			html.EscapeString(loc),
		))
	}
	b.WriteString("</tbody></table>\n")

	b.WriteString("<h2>Automated Pen-Test Checks</h2>\n")
	b.WriteString("<table><thead><tr><th>ID</th><th>Check</th><th>Status</th><th>Severity</th><th>Details</th></tr></thead><tbody>\n")
	for _, pt := range card.PenTestResults {
		b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(pt.ID),
			html.EscapeString(pt.Name),
			html.EscapeString(pt.Status),
			html.EscapeString(string(pt.Severity)),
			html.EscapeString(pt.Details),
		))
	}
	b.WriteString("</tbody></table>\n")

	b.WriteString("<h2>Grafana k6 Load Test &amp; Container Memory-Leak Telemetry</h2>\n")
	if card.LoadTest != nil {
		b.WriteString(fmt.Sprintf("<table><thead><tr><th>Profile</th><th>Passed</th><th>Total Requests</th><th>RPS</th><th>Avg (ms)</th><th>P95 (ms)</th><th>P99 (ms)</th><th>Error Rate</th></tr></thead><tbody><tr><td>%s</td><td>%v</td><td>%d</td><td>%.2f</td><td>%.2f</td><td>%.2f</td><td>%.2f</td><td>%.4f</td></tr></tbody></table>\n",
			html.EscapeString(card.LoadTest.Profile),
			card.LoadTest.Passed,
			card.LoadTest.TotalRequests,
			card.LoadTest.RPS,
			card.LoadTest.AvgMs,
			card.LoadTest.P95Ms,
			card.LoadTest.P99Ms,
			card.LoadTest.ErrorRate,
		))
	}
	if card.MemoryAnalysis != nil {
		b.WriteString(fmt.Sprintf("<table><thead><tr><th>Initial RSS (bytes)</th><th>Final RSS (bytes)</th><th>Peak RSS (bytes)</th><th>Drift (%%)</th><th>Leak Detected</th></tr></thead><tbody><tr><td>%d</td><td>%d</td><td>%d</td><td>%.2f%%</td><td>%v</td></tr></tbody></table>\n",
			card.MemoryAnalysis.InitialRSSBytes,
			card.MemoryAnalysis.FinalRSSBytes,
			card.MemoryAnalysis.PeakRSSBytes,
			card.MemoryAnalysis.DriftPercent,
			card.MemoryAnalysis.LeakDetected,
		))
	}

	b.WriteString("<h2>Mermaid Dependency Cycle Graph</h2>\n")
	b.WriteString("<pre class=\"mermaid\">" + html.EscapeString(GenerateMermaidDependencyGraph(card)) + "</pre>\n")
	b.WriteString(`<script>
if (typeof cytoscape !== 'undefined') {
  cytoscape({
    container: document.getElementById('cy'),
    elements: ` + string(cytoJSON) + `,
    style: [
      { selector: 'node', style: { 'label': 'data(label)', 'background-color': '#38bdf8', 'color': '#f8fafc', 'font-size': '11px' } },
      { selector: 'node[?toxic]', style: { 'background-color': '#ef4444', 'border-width': 2, 'border-color': '#fecaca' } },
      { selector: 'edge', style: { 'width': 2, 'line-color': '#64748b', 'target-arrow-color': '#64748b', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier' } }
    ],
    layout: { name: 'cose' }
  });
}
</script>
`)
	b.WriteString("</body></html>\n")
	return b.String()
}

func WriteReportBundle(outputDir string, card types.ConformanceScorecard, policyRes types.PolicyEvaluationResult) (ReportBundlePaths, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return ReportBundlePaths{}, err
	}

	paths := ReportBundlePaths{
		ScorecardPath: filepath.Join(outputDir, "scorecard.json"),
		SARIFPath:     filepath.Join(outputDir, "results.sarif"),
		MermaidPath:   filepath.Join(outputDir, "dependency-graph.mmd"),
		HTMLPath:      filepath.Join(outputDir, "dashboard.html"),
	}

	scorecardDoc := struct {
		types.ConformanceScorecard
		PolicyEvaluation types.PolicyEvaluationResult `json:"policyEvaluation"`
	}{
		ConformanceScorecard: card,
		PolicyEvaluation:     policyRes,
	}
	scBytes, err := json.MarshalIndent(scorecardDoc, "", "  ")
	if err != nil {
		return paths, err
	}
	if err := os.WriteFile(paths.ScorecardPath, scBytes, 0644); err != nil {
		return paths, err
	}

	sarifBytes, err := GenerateSARIFReport(card)
	if err != nil {
		return paths, err
	}
	if err := os.WriteFile(paths.SARIFPath, sarifBytes, 0644); err != nil {
		return paths, err
	}

	mmd := GenerateMermaidDependencyGraph(card)
	if err := os.WriteFile(paths.MermaidPath, []byte(mmd), 0644); err != nil {
		return paths, err
	}

	htmlContent := GenerateHTMLDashboard(card, policyRes)
	if err := os.WriteFile(paths.HTMLPath, []byte(htmlContent), 0644); err != nil {
		return paths, err
	}

	return paths, nil
}
