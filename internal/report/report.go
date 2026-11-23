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
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			b.WriteByte(ch)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func escapeMermaidLabel(raw string) string {
	s := strings.ReplaceAll(raw, `"`, `'`)
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
	var results []map[string]any
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

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Conformance Audit Dashboard — ` + html.EscapeString(card.TargetName) + `</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; margin: 24px; background: #0f172a; color: #f8fafc; }
  h1, h2 { color: #e2e8f0; }
  .badge { padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 12px; }
  .pass { background: #166534; color: #dcfce7; }
  .fail { background: #991b1b; color: #fee2e2; }
  .toxic { background: #7f1d1d; color: #fecaca; border: 1px solid #ef4444; }
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

	allCycles := append([]types.CycleFinding{}, card.SourceGraph.Cycles...)
	allCycles = append(allCycles, card.PackageGraph.Cycles...)
	b.WriteString("<h2>Dependency Cycles &amp; Toxic Cycle Analysis</h2>\n")
	b.WriteString("<table><thead><tr><th>ID</th><th>Graph</th><th>Toxicity</th><th>Severity</th><th>Cycle Path</th><th>Reasons</th></tr></thead><tbody>\n")
	for _, c := range allCycles {
		toxBadge := `<span class="badge"> Architectural Cycle </span>`
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

	b.WriteString("<h2>Mermaid Dependency Cycle Graph</h2>\n")
	b.WriteString("<pre class=\"mermaid\">" + html.EscapeString(GenerateMermaidDependencyGraph(card)) + "</pre>\n")
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
