package graph

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func canonicalizeCycle(nodes []string) []string {
	if len(nodes) == 0 {
		return nil
	}
	minIdx := 0
	for i := 1; i < len(nodes); i++ {
		if nodes[i] < nodes[minIdx] {
			minIdx = i
		}
	}
	rotated := make([]string, 0, len(nodes)+1)
	rotated = append(rotated, nodes[minIdx:]...)
	rotated = append(rotated, nodes[:minIdx]...)
	rotated = append(rotated, rotated[0])
	return rotated
}

func FindGraphCycles(g types.DependencyGraph, graphType string, findings []types.SecurityFinding) []types.CycleFinding {
	nodeByID := make(map[string]types.GraphNode, len(g.Nodes))
	for _, n := range g.Nodes {
		nodeByID[n.ID] = n
	}

	adj := make(map[string][]string)
	for _, e := range g.Edges {
		if e.From == e.To {
			continue
		}
		adj[e.From] = append(adj[e.From], e.To)
	}
	for k := range adj {
		sort.Strings(adj[k])
	}

	// Tarjan's SCC algorithm
	index := 0
	indices := make(map[string]int)
	lowlink := make(map[string]int)
	onStack := make(map[string]bool)
	var stack []string
	var sccs [][]string

	var strongconnect func(v string)
	strongconnect = func(v string) {
		indices[v] = index
		lowlink[v] = index
		index++
		stack = append(stack, v)
		onStack[v] = true

		for _, w := range adj[v] {
			if _, visited := indices[w]; !visited {
				strongconnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] {
				if indices[w] < lowlink[v] {
					lowlink[v] = indices[w]
				}
			}
		}

		if lowlink[v] == indices[v] {
			var comp []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				comp = append(comp, w)
				if w == v {
					break
				}
			}
			if len(comp) > 1 {
				sort.Strings(comp)
				sccs = append(sccs, comp)
			}
		}
	}

	for _, n := range g.Nodes {
		if _, visited := indices[n.ID]; !visited {
			strongconnect(n.ID)
		}
	}

	// Enumerate canonical elementary cycles inside each non-trivial SCC
	seenSignatures := make(map[string]bool)
	var rawCycles [][]string
	const maxCycles = 50

	for _, comp := range sccs {
		inComp := make(map[string]bool, len(comp))
		for _, id := range comp {
			inComp[id] = true
		}

		for _, startNode := range comp {
			if len(rawCycles) >= maxCycles {
				break
			}
			visited := make(map[string]bool)
			var path []string

			var dfs func(curr string)
			dfs = func(curr string) {
				if len(rawCycles) >= maxCycles {
					return
				}
				visited[curr] = true
				path = append(path, curr)

				for _, next := range adj[curr] {
					if !inComp[next] || next < startNode {
						continue
					}
					if next == startNode && len(path) > 1 {
						canon := canonicalizeCycle(path)
						sig := strings.Join(canon, "->")
						if !seenSignatures[sig] {
							seenSignatures[sig] = true
							rawCycles = append(rawCycles, canon)
						}
					} else if !visited[next] && len(path) < 12 {
						dfs(next)
					}
				}

				path = path[:len(path)-1]
				visited[curr] = false
			}

			dfs(startNode)
		}

		// Fallback for SCCs whose shortest cycle is >= 12 nodes: find shortest cycle via BFS
		foundInComp := false
		for _, cyc := range rawCycles {
			if len(cyc) > 0 && inComp[cyc[0]] {
				foundInComp = true
				break
			}
		}
		if !foundInComp && len(comp) > 1 {
			startNode := comp[0]
			parent := make(map[string]string)
			queue := []string{startNode}
			parent[startNode] = startNode
			var backNode string
			for len(queue) > 0 && backNode == "" {
				u := queue[0]
				queue = queue[1:]
				for _, v := range adj[u] {
					if !inComp[v] {
						continue
					}
					if v == startNode && u != startNode {
						backNode = u
						break
					}
					if _, seen := parent[v]; !seen {
						parent[v] = u
						queue = append(queue, v)
					}
				}
			}
			if backNode != "" {
				var rev []string
				for cur := backNode; cur != startNode; cur = parent[cur] {
					rev = append(rev, cur)
				}
				rev = append(rev, startNode)
				slices.Reverse(rev)
				canon := canonicalizeCycle(rev)
				sig := strings.Join(canon, "->")
				if !seenSignatures[sig] {
					seenSignatures[sig] = true
					rawCycles = append(rawCycles, canon)
				}
			}
		}
	}

	sort.Slice(rawCycles, func(i, j int) bool {
		return strings.Join(rawCycles[i], "->") < strings.Join(rawCycles[j], "->")
	})

	var results []types.CycleFinding
	for i, cycNodes := range rawCycles {
		uniqueNodes := cycNodes[:len(cycNodes)-1]
		var reasons []string
		var relatedFindings []string
		hasHighOrCriticalFinding := false
		hasFinding := false
		hasSensitiveSink := false

		for _, nodeID := range uniqueNodes {
			node := nodeByID[nodeID]
			for _, sink := range node.Sinks {
				if sink == "auth" || sink == "crypto" || sink == "db" || sink == "exec" {
					hasSensitiveSink = true
					reason := fmt.Sprintf("Touches sensitive %s sink (%s)", sink, nodeID)
					if !slices.Contains(reasons, reason) {
						reasons = append(reasons, reason)
					}
				}
			}
			for _, cve := range node.CVEs {
				hasFinding = true
				hasHighOrCriticalFinding = true
				reason := fmt.Sprintf("Package %s has vulnerability %s", node.Label, cve)
				if !slices.Contains(reasons, reason) {
					reasons = append(reasons, reason)
				}
			}
			for _, fID := range node.Findings {
				if !slices.Contains(relatedFindings, fID) {
					relatedFindings = append(relatedFindings, fID)
				}
			}

			for _, f := range findings {
				matchesFile := f.FilePath != "" && f.FilePath == nodeID
				matchesPkg := f.PackageName != "" && (node.Label == f.PackageName || strings.HasPrefix(node.Label, f.PackageName+"@") || strings.Contains(nodeID, "/"+f.PackageName+"@"))
				if matchesFile || matchesPkg {
					hasFinding = true
					if f.Severity == types.SeverityCritical || f.Severity == types.SeverityHigh {
						hasHighOrCriticalFinding = true
					}
					if !slices.Contains(relatedFindings, f.ID) {
						relatedFindings = append(relatedFindings, f.ID)
					}
					reason := fmt.Sprintf("Contains %s %s finding (%s)", f.Tool, f.Severity, f.Title)
					if !slices.Contains(reasons, reason) {
						reasons = append(reasons, reason)
					}
				}
			}
		}

		isToxic := hasFinding || (hasSensitiveSink && len(uniqueNodes) >= 2)
		sev := types.SeverityMedium
		if hasHighOrCriticalFinding {
			sev = types.SeverityCritical
		} else if isToxic {
			sev = types.SeverityHigh
		}

		results = append(results, types.CycleFinding{
			ID:              fmt.Sprintf("%s-cycle-%d", graphType, i+1),
			GraphType:       graphType,
			Nodes:           cycNodes,
			IsToxic:         isToxic,
			Severity:        sev,
			Reasons:         reasons,
			RelatedFindings: relatedFindings,
		})
	}

	return results
}

func AnalyzeDependencyGraphs(sourceGraph, sbomGraph types.DependencyGraph, findings []types.SecurityFinding) (types.DependencyGraph, types.DependencyGraph) {
	// Annotate sourceGraph nodes with matching findings
	for i := range sourceGraph.Nodes {
		for _, f := range findings {
			if f.FilePath != "" && f.FilePath == sourceGraph.Nodes[i].ID {
				if !slices.Contains(sourceGraph.Nodes[i].Findings, f.ID) {
					sourceGraph.Nodes[i].Findings = append(sourceGraph.Nodes[i].Findings, f.ID)
				}
			}
		}
	}
	sourceGraph.Cycles = FindGraphCycles(sourceGraph, "source", findings)
	sbomGraph.Cycles = FindGraphCycles(sbomGraph, "package", findings)
	return sourceGraph, sbomGraph
}
