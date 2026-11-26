package graph

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/runner"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

//go:embed kev_catalog.json
var embeddedKEVCatalog []byte

var (
	kevOnce sync.Once
	kevSet  map[string]bool
)

func loadKEVCatalog() map[string]bool {
	kevOnce.Do(func() {
		kevSet = make(map[string]bool)
		var doc struct {
			Vulnerabilities []struct {
				CVEID string `json:"cveID"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(embeddedKEVCatalog, &doc); err == nil {
			for _, v := range doc.Vulnerabilities {
				id := strings.ToUpper(strings.TrimSpace(v.CVEID))
				if id != "" {
					kevSet[id] = true
				}
			}
		}
	})
	return kevSet
}

func isKnownExploitedCVE(id string) bool {
	return loadKEVCatalog()[strings.ToUpper(strings.TrimSpace(id))]
}

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

type osvVulnerability struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

type osvDoc struct {
	Results []struct {
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

func buildOSVFinding(pkgName, pkgVersion string, v osvVulnerability) types.SecurityFinding {
	category := types.CategorySCA
	var severity types.Severity
	cvssFound := false
	for _, sevEntry := range v.Severity {
		if parsed, ok := ParseCVSSSeverity(sevEntry.Score); ok {
			if !cvssFound || severityRank(parsed) > severityRank(severity) {
				severity = parsed
				cvssFound = true
			}
		}
	}
	if !cvssFound {
		severity = mapOSVSeverity(v.DatabaseSpecific.Severity)
	}
	isKEV := isKnownExploitedCVE(v.ID)
	for _, alias := range v.Aliases {
		if isKnownExploitedCVE(alias) {
			isKEV = true
			break
		}
	}
	if isKEV {
		severity = types.SeverityCritical
	}
	cveID := strings.TrimSpace(v.ID)
	if !strings.HasPrefix(strings.ToUpper(cveID), "CVE-") {
		for _, alias := range v.Aliases {
			trimmed := strings.TrimSpace(alias)
			if strings.HasPrefix(strings.ToUpper(trimmed), "CVE-") {
				cveID = trimmed
				break
			}
		}
	}
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(v.ID)), "MAL-") {
		category = types.CategoryMalware
		severity = types.SeverityCritical
	}
	return types.SecurityFinding{
		ID:          fmt.Sprintf("osv-%s-%s", pkgName, v.ID),
		Category:    category,
		Tool:        "osv-scanner",
		Severity:    severity,
		Title:       fmt.Sprintf("%s in %s@%s", v.ID, pkgName, pkgVersion),
		Description: v.Summary,
		CVE:         cveID,
		PackageName: pkgName,
		KEV:         isKEV,
	}
}

func severityRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 4
	case types.SeverityHigh:
		return 3
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 1
	default:
		return 0
	}
}

func scoreToSeverity(score float64) types.Severity {
	switch {
	case score >= 9.0:
		return types.SeverityCritical
	case score >= 7.0:
		return types.SeverityHigh
	case score >= 4.0:
		return types.SeverityMedium
	case score > 0.0:
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

func roundUpCVSS(x float64) float64 {
	intInput := math.Round(x * 100000)
	if int(intInput)%10000 == 0 {
		return intInput / 100000.0
	}
	return (math.Floor(intInput/10000.0) + 1.0) / 10.0
}

func computeCVSSv3BaseScore(metrics map[string]string) (float64, bool) {
	avMap := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acMap := map[string]float64{"L": 0.77, "H": 0.44}
	uiMap := map[string]float64{"N": 0.85, "R": 0.62}
	ciaMap := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}

	av, ok1 := avMap[metrics["AV"]]
	ac, ok2 := acMap[metrics["AC"]]
	ui, ok3 := uiMap[metrics["UI"]]
	c, ok4 := ciaMap[metrics["C"]]
	i, ok5 := ciaMap[metrics["I"]]
	a, ok6 := ciaMap[metrics["A"]]
	scope := metrics["S"]
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || (scope != "U" && scope != "C") {
		return 0, false
	}

	var pr float64
	switch metrics["PR"] {
	case "N":
		pr = 0.85
	case "L":
		if scope == "C" {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if scope == "C" {
			pr = 0.50
		} else {
			pr = 0.27
		}
	default:
		return 0, false
	}

	iss := 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0.0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	var base float64
	if scope == "U" {
		base = math.Min(impact+exploitability, 10.0)
	} else {
		base = math.Min(1.08*(impact+exploitability), 10.0)
	}
	return roundUpCVSS(base), true
}

func computeCVSSv4ApproxScore(metrics map[string]string) (float64, bool) {
	ciaMap := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	vc, ok1 := ciaMap[metrics["VC"]]
	vi, ok2 := ciaMap[metrics["VI"]]
	va, ok3 := ciaMap[metrics["VA"]]
	if !ok1 || !ok2 || !ok3 {
		return 0, false
	}
	sc := ciaMap[metrics["SC"]]
	si := ciaMap[metrics["SI"]]
	sa := ciaMap[metrics["SA"]]
	maxImpact := math.Max(1.0-(1.0-vc)*(1.0-vi)*(1.0-va), 1.0-(1.0-sc)*(1.0-si)*(1.0-sa))
	if maxImpact <= 0 {
		return 0.0, true
	}
	av := 0.85
	switch metrics["AV"] {
	case "A":
		av = 0.62
	case "L":
		av = 0.55
	case "P":
		av = 0.20
	}
	ac := 0.77
	if metrics["AC"] == "H" || metrics["AT"] == "P" {
		ac = 0.44
	}
	pr := 0.85
	switch metrics["PR"] {
	case "L":
		pr = 0.62
	case "H":
		pr = 0.27
	}
	ui := 0.85
	if metrics["UI"] == "P" || metrics["UI"] == "A" {
		ui = 0.62
	}
	score := math.Min(10.0, 6.42*maxImpact+8.22*av*ac*pr*ui)
	return roundUpCVSS(score), true
}

// ParseCVSSSeverity parses a numeric CVSS score (e.g. "7.5") or a CVSS v3.x / v4.0 vector
// string and returns the mapped Severity.
func ParseCVSSSeverity(vectorOrScore string) (types.Severity, bool) {
	raw := strings.TrimSpace(vectorOrScore)
	if raw == "" {
		return "", false
	}
	if num, err := strconv.ParseFloat(raw, 64); err == nil && num >= 0 && num <= 10 {
		return scoreToSeverity(num), true
	}

	upper := strings.ToUpper(raw)
	if strings.HasPrefix(upper, "CVSS:3.0/") || strings.HasPrefix(upper, "CVSS:3.1/") {
		metrics := make(map[string]string)
		for _, part := range strings.Split(upper, "/")[1:] {
			if kv := strings.SplitN(part, ":", 2); len(kv) == 2 {
				metrics[kv[0]] = kv[1]
			}
		}
		if score, ok := computeCVSSv3BaseScore(metrics); ok {
			return scoreToSeverity(score), true
		}
	}
	if strings.HasPrefix(upper, "CVSS:4.0/") {
		metrics := make(map[string]string)
		for _, part := range strings.Split(upper, "/")[1:] {
			if kv := strings.SplitN(part, ":", 2); len(kv) == 2 {
				metrics[kv[0]] = kv[1]
			}
		}
		if score, ok := computeCVSSv4ApproxScore(metrics); ok {
			return scoreToSeverity(score), true
		}
	}
	return "", false
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
		return types.SeverityMedium
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
					finding := buildOSVFinding(pkg.Package.Name, pkg.Package.Version, v)
					findings = append(findings, finding)
					if node, exists := nodeMap[ref]; exists {
						if !slices.Contains(node.CVEs, v.ID) {
							node.CVEs = append(node.CVEs, v.ID)
						}
						if !slices.Contains(node.Findings, finding.ID) {
							node.Findings = append(node.Findings, finding.ID)
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
	parentDir, outDir, err := runner.CreateIsolatedWorkDir("sbom-conformance-")
	if err != nil {
		return types.DependencyGraph{}, nil, err
	}
	defer os.RemoveAll(parentDir)

	sbomHostPath := filepath.Join(outDir, "bom.json")
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
		WorkDir:          outDir,
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

var epssBaseURL = "https://api.first.org/data/v1/epss"

// EnrichFindingsWithEPSS optionally queries the FIRST EPSS API (3s timeout) when
// onlineEnrich is true, populating EPSS scores on CVE findings and degrading cleanly offline.
func EnrichFindingsWithEPSS(ctx context.Context, findings []types.SecurityFinding, onlineEnrich bool) []types.SecurityFinding {
	out := make([]types.SecurityFinding, len(findings))
	copy(out, findings)
	if !onlineEnrich {
		return out
	}

	client := &http.Client{Timeout: 3 * time.Second}
	cache := make(map[string]float64)

	for i := range out {
		cve := strings.ToUpper(strings.TrimSpace(out[i].CVE))
		if !strings.HasPrefix(cve, "CVE-") {
			continue
		}
		if score, cached := cache[cve]; cached {
			out[i].EPSS = score
			continue
		}
		reqURL := epssBaseURL + "?cve=" + url.QueryEscape(cve)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		var payload struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if resp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(resp.Body).Decode(&payload); err == nil && len(payload.Data) > 0 {
				if val, parseErr := strconv.ParseFloat(strings.TrimSpace(payload.Data[0].EPSS), 64); parseErr == nil {
					cache[cve] = val
					out[i].EPSS = val
				}
			}
		}
		resp.Body.Close()
	}
	return out
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

