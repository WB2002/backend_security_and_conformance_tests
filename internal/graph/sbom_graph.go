package graph

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

type cycloneDXDoc struct {
	Components []struct {
		BomRef  string `json:"bom-ref"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
	} `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

type osvDoc struct {
	Results []struct {
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID               string `json:"id"`
				Summary          string `json:"summary"`
				DatabaseSpecific struct {
					Severity string `json:"severity"`
				} `json:"database_specific"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

func mapOSVSeverity(raw string) types.Severity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH":
		return types.SeverityHigh
	case "MODERATE", "MEDIUM":
		return types.SeverityMedium
	case "LOW":
		return types.SeverityLow
	default:
		return types.SeverityHigh
	}
}

func ParseCycloneDXSBOMGraph(cdxJSON []byte, osvJSON []byte) (types.DependencyGraph, []types.SecurityFinding, error) {
	var g types.DependencyGraph
	var findings []types.SecurityFinding

	if len(strings.TrimSpace(string(cdxJSON))) == 0 {
		return g, nil, nil
	}

	var cdx cycloneDXDoc
	if err := json.Unmarshal(cdxJSON, &cdx); err != nil {
		return g, nil, fmt.Errorf("parse cyclonedx sbom: %w", err)
	}

	nodeMap := make(map[string]*types.GraphNode)
	nameVerToRef := make(map[string]string)

	for _, comp := range cdx.Components {
		ref := comp.BomRef
		if ref == "" {
			ref = comp.Purl
		}
		if ref == "" {
			ref = fmt.Sprintf("%s@%s", comp.Name, comp.Version)
		}
		label := comp.Name
		if comp.Version != "" {
			label = fmt.Sprintf("%s@%s", comp.Name, comp.Version)
		}
		nodeMap[ref] = &types.GraphNode{
			ID:      ref,
			Label:   label,
			Type:    "package",
			Version: comp.Version,
		}
		nameVerToRef[fmt.Sprintf("%s@%s", comp.Name, comp.Version)] = ref
		nameVerToRef[comp.Name] = ref
	}

	edgeSet := make(map[string]types.GraphEdge)
	for _, dep := range cdx.Dependencies {
		if dep.Ref == "" {
			continue
		}
		if _, exists := nodeMap[dep.Ref]; !exists {
			nodeMap[dep.Ref] = &types.GraphNode{
				ID:    dep.Ref,
				Label: dep.Ref,
				Type:  "package",
			}
		}
		for _, target := range dep.DependsOn {
			if target == "" || target == dep.Ref {
				continue
			}
			if _, exists := nodeMap[target]; !exists {
				nodeMap[target] = &types.GraphNode{
					ID:    target,
					Label: target,
					Type:  "package",
				}
			}
			key := dep.Ref + "->" + target
			edgeSet[key] = types.GraphEdge{
				From: dep.Ref,
				To:   target,
				Kind: "dependency",
			}
		}
	}

	if len(strings.TrimSpace(string(osvJSON))) > 0 {
		var osv osvDoc
		if err := json.Unmarshal(osvJSON, &osv); err != nil {
			return g, nil, fmt.Errorf("parse osv json: %w", err)
		}
		for _, res := range osv.Results {
			for _, pkg := range res.Packages {
				ref, ok := nameVerToRef[fmt.Sprintf("%s@%s", pkg.Package.Name, pkg.Package.Version)]
				if !ok {
					ref = nameVerToRef[pkg.Package.Name]
				}
				for _, v := range pkg.Vulnerabilities {
					fID := fmt.Sprintf("osv-%s-%s", pkg.Package.Name, v.ID)
					findings = append(findings, types.SecurityFinding{
						ID:          fID,
						Category:    types.CategorySCA,
						Tool:        "osv-scanner",
						Severity:    mapOSVSeverity(v.DatabaseSpecific.Severity),
						Title:       fmt.Sprintf("%s in %s@%s", v.ID, pkg.Package.Name, pkg.Package.Version),
						Description: v.Summary,
						CVE:         v.ID,
						PackageName: pkg.Package.Name,
					})
					if node, exists := nodeMap[ref]; exists {
						if !slices.Contains(node.CVEs, v.ID) {
							node.CVEs = append(node.CVEs, v.ID)
						}
						if !slices.Contains(node.Findings, fID) {
							node.Findings = append(node.Findings, fID)
						}
					}
				}
			}
		}
	}

	for _, n := range nodeMap {
		g.Nodes = append(g.Nodes, *n)
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })

	for _, e := range edgeSet {
		g.Edges = append(g.Edges, e)
	}
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		return g.Edges[i].To < g.Edges[j].To
	})

	return g, findings, nil
}
