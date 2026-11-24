package graph

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/runner"
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

func RunSBOMAndOSVScan(ctx context.Context, targetDir string, mode runner.ExecutionMode, execFn runner.CommandExecutor) (types.DependencyGraph, []types.SecurityFinding, error) {
	tmpDir, err := os.MkdirTemp("", "sbom-conformance-*")
	if err != nil {
		return types.DependencyGraph{}, nil, err
	}
	defer os.RemoveAll(tmpDir)
	if err := os.Chmod(tmpDir, 0o777); err != nil {
		return types.DependencyGraph{}, nil, err
	}

	sbomHostPath := filepath.Join(tmpDir, "bom.json")
	sbomArgPath := sbomHostPath
	scanTarget := targetDir
	if runner.ResolveEffectiveMode(mode, runner.ToolCdxgen) == runner.ModeDocker {
		sbomArgPath = "/out/bom.json"
		scanTarget = "/workspace"
	}

	_, err = runner.RunTool(ctx, runner.ToolInvocationOptions{
		Tool:             runner.ToolCdxgen,
		Args:             []string{"-r", "-o", sbomArgPath, scanTarget},
		TargetDir:        targetDir,
		WorkDir:          tmpDir,
		Mode:             mode,
		AllowedExitCodes: []int{0, 1},
	}, execFn)
	if err != nil {
		return types.DependencyGraph{}, nil, fmt.Errorf("cdxgen execution failed: %w", err)
	}

	cdxBytes, _ := os.ReadFile(sbomHostPath)

	osvTarget := targetDir
	if runner.ResolveEffectiveMode(mode, runner.ToolOSVScanner) == runner.ModeDocker {
		osvTarget = "/workspace"
	}
	osvRes, err := runner.RunTool(ctx, runner.ToolInvocationOptions{
		Tool:             runner.ToolOSVScanner,
		Args:             []string{"scan", "--format", "json", "-r", osvTarget},
		TargetDir:        targetDir,
		Mode:             mode,
		AllowedExitCodes: []int{0, 1},
	}, execFn)
	if err != nil {
		return types.DependencyGraph{}, nil, fmt.Errorf("osv-scanner execution failed: %w", err)
	}

	g, findings, err := ParseCycloneDXSBOMGraph(cdxBytes, []byte(osvRes.Stdout))
	if err != nil {
		return g, findings, err
	}

	peerDeps := LoadNPMPeerDependencies(targetDir)
	if len(peerDeps) > 0 {
		g = FilterPeerDependencyEdges(g, peerDeps)
	}

	return g, findings, nil
}

// parseNPMPurl extracts (packageName, version) from a CycloneDX npm PURL such as
// "pkg:npm/@eslint-community/eslint-utils@4.9.1" or "pkg:npm/pg-pool@3.11.0".
func parseNPMPurl(ref string) (string, string, bool) {
	if !strings.HasPrefix(ref, "pkg:npm/") {
		return "", "", false
	}
	rest := strings.TrimPrefix(ref, "pkg:npm/")
	if idx := strings.IndexAny(rest, "?#"); idx >= 0 {
		rest = rest[:idx]
	}
	if decoded, err := url.PathUnescape(rest); err == nil {
		rest = decoded
	}
	at := strings.LastIndex(rest, "@")
	if at <= 0 {
		return rest, "", rest != ""
	}
	return rest[:at], rest[at+1:], true
}

func unquoteYAMLKey(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) >= 2 && ((s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"')) {
		return s[1 : len(s)-1]
	}
	return s
}

func parsePnpmPackageKey(rawKey string) (string, string) {
	key := strings.TrimPrefix(unquoteYAMLKey(rawKey), "/")
	// Strip pnpm peer-resolution suffix e.g. "pg-pool@3.11.0(pg@8.18.0)"
	if idx := strings.Index(key, "("); idx >= 0 {
		key = key[:idx]
	}
	at := strings.LastIndex(key, "@")
	if at <= 0 {
		return key, ""
	}
	return key[:at], key[at+1:]
}

// ParsePnpmLockPeerDependencies extracts peerDependencies declared under the
// top-level `packages:` section of a pnpm-lock.yaml (v6/v9).
// Returns map["pkgName@version"] -> set of peer dependency package names.
func ParsePnpmLockPeerDependencies(content []byte) map[string]map[string]bool {
	result := make(map[string]map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	inPackages := false
	inPeerDeps := false
	currentPkgKey := ""

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			inPackages = strings.HasPrefix(trimmed, "packages:")
			inPeerDeps = false
			currentPkgKey = ""
			continue
		}
		if !inPackages {
			continue
		}

		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			name, ver := parsePnpmPackageKey(strings.TrimSuffix(trimmed, ":"))
			if name != "" && ver != "" {
				currentPkgKey = name + "@" + ver
			} else {
				currentPkgKey = ""
			}
			inPeerDeps = false
			continue
		}

		if indent == 4 {
			inPeerDeps = trimmed == "peerDependencies:"
			continue
		}

		if inPeerDeps && indent == 6 && currentPkgKey != "" {
			if colon := strings.Index(trimmed, ":"); colon > 0 {
				peerName := unquoteYAMLKey(trimmed[:colon])
				if peerName != "" {
					if result[currentPkgKey] == nil {
						result[currentPkgKey] = make(map[string]bool)
					}
					result[currentPkgKey][peerName] = true
				}
			}
		}
	}

	return result
}

type packageLockDoc struct {
	Packages map[string]struct {
		Name             string            `json:"name"`
		Version          string            `json:"version"`
		PeerDependencies map[string]string `json:"peerDependencies"`
	} `json:"packages"`
}

// ParsePackageLockPeerDependencies extracts peerDependencies from npm package-lock.json (v2/v3).
func ParsePackageLockPeerDependencies(content []byte) map[string]map[string]bool {
	var doc packageLockDoc
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil
	}
	result := make(map[string]map[string]bool)
	for path, pkg := range doc.Packages {
		if len(pkg.PeerDependencies) == 0 || pkg.Version == "" {
			continue
		}
		name := pkg.Name
		if name == "" {
			if idx := strings.LastIndex(path, "node_modules/"); idx >= 0 {
				name = path[idx+len("node_modules/"):]
			}
		}
		if name == "" {
			continue
		}
		key := name + "@" + pkg.Version
		if result[key] == nil {
			result[key] = make(map[string]bool)
		}
		for peerName := range pkg.PeerDependencies {
			result[key][peerName] = true
		}
	}
	return result
}

// LoadNPMPeerDependencies loads peerDependencies from pnpm-lock.yaml or package-lock.json in targetDir.
func LoadNPMPeerDependencies(targetDir string) map[string]map[string]bool {
	merged := make(map[string]map[string]bool)
	merge := func(src map[string]map[string]bool) {
		for k, peers := range src {
			if merged[k] == nil {
				merged[k] = make(map[string]bool)
			}
			for p := range peers {
				merged[k][p] = true
			}
		}
	}

	if data, err := os.ReadFile(filepath.Join(targetDir, "pnpm-lock.yaml")); err == nil {
		merge(ParsePnpmLockPeerDependencies(data))
	}
	if data, err := os.ReadFile(filepath.Join(targetDir, "package-lock.json")); err == nil {
		merge(ParsePackageLockPeerDependencies(data))
	}
	return merged
}

// FilterPeerDependencyEdges removes edges where the source package declares the target package
// as a peerDependency (host-provided contract rather than a hard runtime dependency).
func FilterPeerDependencyEdges(g types.DependencyGraph, peerDeps map[string]map[string]bool) types.DependencyGraph {
	if len(peerDeps) == 0 || len(g.Edges) == 0 {
		return g
	}
	filtered := make([]types.GraphEdge, 0, len(g.Edges))
	for _, e := range g.Edges {
		fromName, fromVer, fromOK := parseNPMPurl(e.From)
		toName, _, toOK := parseNPMPurl(e.To)
		if fromOK && toOK && fromVer != "" {
			if peers := peerDeps[fromName+"@"+fromVer]; peers[toName] {
				continue
			}
		}
		filtered = append(filtered, e)
	}
	g.Edges = filtered
	return g
}

