package graph

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func boolPtr(v bool) *bool {
	return &v
}

func normalizePkgName(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	if strings.HasPrefix(s, "pkg:") {
		// e.g. pkg:npm/%40scope/pkg@1.0.0 or pkg:golang/github.com/a/b@v1.0.0
		if slash := strings.Index(s, "/"); slash >= 0 {
			rest := s[slash+1:]
			if q := strings.IndexAny(rest, "?#"); q >= 0 {
				rest = rest[:q]
			}
			if decoded, err := url.PathUnescape(rest); err == nil {
				rest = decoded
			}
			if at := strings.LastIndex(rest, "@"); at > 0 {
				rest = rest[:at]
			}
			return strings.ToLower(strings.TrimSpace(rest))
		}
	}
	// Label form: "pkg@1.2.3" or "@scope/pkg@1.2.3"
	if at := strings.LastIndex(s, "@"); at > 0 {
		s = s[:at]
	}
	return s
}

func isEntrypointModule(filePath string) bool {
	lower := strings.ToLower(filepath.ToSlash(filePath))
	base := path.Base(lower)
	if base == "main.go" || base == "app.module.ts" || base == "urls.py" ||
		base == "main.ts" || base == "main.js" || base == "server.ts" || base == "server.js" ||
		base == "app.py" || base == "main.py" || base == "router.ex" || base == "endpoint.ex" {
		return true
	}
	if strings.HasPrefix(lower, "cmd/") || strings.Contains(lower, "/cmd/") {
		return true
	}
	if strings.Contains(lower, "controller") || strings.Contains(lower, "router") || strings.Contains(lower, "route") {
		return true
	}
	return false
}

// LinkSourceToPackageReachability connects source nodes' ExternalImports to matching
// package graph nodes via "external-import" edges, BFS-traverses from entrypoint/route
// modules, and marks SCA/malware findings as Reachable = true/false.
func LinkSourceToPackageReachability(
	srcGraph, pkgGraph types.DependencyGraph,
	findings []types.SecurityFinding,
) (types.DependencyGraph, types.DependencyGraph, []types.SecurityFinding) {
	outFindings := make([]types.SecurityFinding, len(findings))
	copy(outFindings, findings)
	if len(pkgGraph.Nodes) == 0 {
		return srcGraph, pkgGraph, outFindings
	}

	pkgByName := make(map[string][]string)
	for _, n := range pkgGraph.Nodes {
		names := []string{
			normalizePkgName(n.ID),
			normalizePkgName(n.Label),
		}
		for _, nm := range names {
			if nm == "" {
				continue
			}
			if !slices.Contains(pkgByName[nm], n.ID) {
				pkgByName[nm] = append(pkgByName[nm], n.ID)
			}
		}
	}

	matchExternalToPkgIDs := func(ext string) []string {
		norm := strings.ToLower(strings.TrimSpace(ext))
		if norm == "" {
			return nil
		}
		if ids, ok := pkgByName[norm]; ok {
			return ids
		}
		// Match Go subpackages (e.g. github.com/gin-gonic/gin/binding -> github.com/gin-gonic/gin)
		var matched []string
		for pkgName, ids := range pkgByName {
			if strings.HasPrefix(norm, pkgName+"/") {
				for _, id := range ids {
					if !slices.Contains(matched, id) {
						matched = append(matched, id)
					}
				}
			}
		}
		return matched
	}

	edgeKey := func(from, to, kind string) string {
		return from + "->" + to + "|" + kind
	}
	seenEdges := make(map[string]bool, len(srcGraph.Edges))
	for _, e := range srcGraph.Edges {
		seenEdges[edgeKey(e.From, e.To, e.Kind)] = true
	}

	adj := make(map[string][]string)
	for _, e := range srcGraph.Edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	for _, e := range pkgGraph.Edges {
		adj[e.From] = append(adj[e.From], e.To)
	}

	for _, n := range srcGraph.Nodes {
		for _, ext := range n.ExternalImports {
			for _, pkgID := range matchExternalToPkgIDs(ext) {
				k := edgeKey(n.ID, pkgID, "external-import")
				if !seenEdges[k] {
					seenEdges[k] = true
					srcGraph.Edges = append(srcGraph.Edges, types.GraphEdge{
						From: n.ID,
						To:   pkgID,
						Kind: "external-import",
					})
				}
				adj[n.ID] = append(adj[n.ID], pkgID)
			}
		}
	}

	// BFS from entrypoint/route modules
	var queue []string
	visited := make(map[string]bool)
	for _, n := range srcGraph.Nodes {
		if isEntrypointModule(n.ID) {
			visited[n.ID] = true
			queue = append(queue, n.ID)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range adj[cur] {
			if !visited[next] {
				visited[next] = true
				queue = append(queue, next)
			}
		}
	}

	pkgNodeByID := make(map[string]types.GraphNode, len(pkgGraph.Nodes))
	for _, n := range pkgGraph.Nodes {
		pkgNodeByID[n.ID] = n
	}

	for i := range outFindings {
		f := &outFindings[i]
		if f.Category != types.CategorySCA && !(f.Category == types.CategoryMalware && f.PackageName != "") {
			continue
		}
		if f.Reachable != nil && *f.Reachable {
			continue
		}
		reachable := false
		if f.PackageName != "" {
			for _, id := range matchExternalToPkgIDs(f.PackageName) {
				if visited[id] {
					reachable = true
					break
				}
			}
		}
		if !reachable {
			for id, n := range pkgNodeByID {
				if !visited[id] {
					continue
				}
				if (f.ID != "" && slices.Contains(n.Findings, f.ID)) ||
					(f.CVE != "" && slices.Contains(n.CVEs, f.CVE)) {
					reachable = true
					break
				}
			}
		}
		f.Reachable = boolPtr(reachable)
	}

	return srcGraph, pkgGraph, outFindings
}

type discoveredRoute struct {
	Method   string
	Path     string
	FilePath string
	Line     int
}

var (
	nestControllerRe = regexp.MustCompile(`@Controller\s*\(\s*['"]([^'"]*)['"]\s*\)`)
	nestMethodRe     = regexp.MustCompile(`@(Get|Post|Put|Patch|Delete)\s*\(\s*(?:['"]([^'"]*)['"])?\s*\)`)
	jsRouteRe        = regexp.MustCompile(`\b(?:app|router|fastify|server)\.(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]`)
	goHandleFuncRe   = regexp.MustCompile(`\.(?:HandleFunc|Handle)\s*\(\s*"([^"]+)"`)
	goMethodRouteRe  = regexp.MustCompile(`\.(Get|Post|Put|Patch|Delete|GET|POST|PUT|PATCH|DELETE)\s*\(\s*"(/[^"]*)"`)
	pyDecoratorRe    = regexp.MustCompile(`@(?:app|router|bp|blueprint)\.(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]`)
	pyDjangoPathRe   = regexp.MustCompile(`\bpath\s*\(\s*['"]([^'"]+)['"]`)
	exScopeRe        = regexp.MustCompile(`^\s*scope\s+"([^"]+)"`)
	exRouteRe        = regexp.MustCompile(`^\s*(get|post|put|patch|delete)\s+"([^"]+)"`)

	pathParamBraceRe = regexp.MustCompile(`\{[^/}]+\}`)
	pathParamColonRe = regexp.MustCompile(`:([A-Za-z0-9_]+)`)
	pathParamAngleRe = regexp.MustCompile(`<[^/>]+>`)
)

func normalizeRoutePath(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "/"
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	for strings.Contains(s, "//") {
		s = strings.ReplaceAll(s, "//", "/")
	}
	if len(s) > 1 {
		s = strings.TrimRight(s, "/")
	}
	return s
}

func canonicalRouteTemplate(p string) string {
	s := normalizeRoutePath(p)
	s = pathParamBraceRe.ReplaceAllString(s, "{}")
	s = pathParamColonRe.ReplaceAllString(s, "{}")
	s = pathParamAngleRe.ReplaceAllString(s, "{}")
	return s
}

func extractRoutesFromFile(filePath, content string) []discoveredRoute {
	ext := strings.ToLower(path.Ext(filePath))
	lines := strings.Split(content, "\n")
	var routes []discoveredRoute

	switch ext {
	case ".ts", ".tsx", ".js", ".mjs", ".cjs":
		controllerPrefix := ""
		if m := nestControllerRe.FindStringSubmatch(content); len(m) > 1 {
			controllerPrefix = m[1]
		}
		for idx, line := range lines {
			lineNo := idx + 1
			if m := nestMethodRe.FindStringSubmatch(line); len(m) > 1 {
				method := strings.ToUpper(m[1])
				sub := ""
				if len(m) > 2 {
					sub = m[2]
				}
				fullPath := normalizeRoutePath(path.Join("/", controllerPrefix, sub))
				routes = append(routes, discoveredRoute{Method: method, Path: fullPath, FilePath: filePath, Line: lineNo})
			}
			for _, m := range jsRouteRe.FindAllStringSubmatch(line, -1) {
				routes = append(routes, discoveredRoute{
					Method:   strings.ToUpper(m[1]),
					Path:     normalizeRoutePath(m[2]),
					FilePath: filePath,
					Line:     lineNo,
				})
			}
		}
	case ".go":
		for idx, line := range lines {
			lineNo := idx + 1
			for _, m := range goHandleFuncRe.FindAllStringSubmatch(line, -1) {
				spec := strings.TrimSpace(m[1])
				method := "ANY"
				routePath := spec
				if parts := strings.Fields(spec); len(parts) == 2 {
					method = strings.ToUpper(parts[0])
					routePath = parts[1]
				}
				routes = append(routes, discoveredRoute{
					Method:   method,
					Path:     normalizeRoutePath(routePath),
					FilePath: filePath,
					Line:     lineNo,
				})
			}
			for _, m := range goMethodRouteRe.FindAllStringSubmatch(line, -1) {
				routes = append(routes, discoveredRoute{
					Method:   strings.ToUpper(m[1]),
					Path:     normalizeRoutePath(m[2]),
					FilePath: filePath,
					Line:     lineNo,
				})
			}
		}
	case ".py":
		for idx, line := range lines {
			lineNo := idx + 1
			for _, m := range pyDecoratorRe.FindAllStringSubmatch(line, -1) {
				routes = append(routes, discoveredRoute{
					Method:   strings.ToUpper(m[1]),
					Path:     normalizeRoutePath(m[2]),
					FilePath: filePath,
					Line:     lineNo,
				})
			}
			for _, m := range pyDjangoPathRe.FindAllStringSubmatch(line, -1) {
				routes = append(routes, discoveredRoute{
					Method:   "ANY",
					Path:     normalizeRoutePath(m[1]),
					FilePath: filePath,
					Line:     lineNo,
				})
			}
		}
	case ".ex":
		if strings.HasSuffix(strings.ToLower(filePath), "router.ex") || strings.Contains(content, "Phoenix.Router") {
			scopePrefix := ""
			for idx, line := range lines {
				lineNo := idx + 1
				if m := exScopeRe.FindStringSubmatch(line); len(m) > 1 {
					scopePrefix = m[1]
				}
				if m := exRouteRe.FindStringSubmatch(line); len(m) > 2 {
					fullPath := normalizeRoutePath(path.Join("/", scopePrefix, m[2]))
					routes = append(routes, discoveredRoute{
						Method:   strings.ToUpper(m[1]),
						Path:     fullPath,
						FilePath: filePath,
						Line:     lineNo,
					})
				}
			}
		}
	}
	return routes
}

func isPublicRoute(routePath string, arch *types.ArchitectureRules) bool {
	norm := normalizeRoutePath(routePath)
	if arch != nil && len(arch.PublicRoutes) > 0 {
		for _, pub := range arch.PublicRoutes {
			p := normalizeRoutePath(strings.TrimSuffix(pub, "*"))
			if strings.HasSuffix(pub, "*") {
				if strings.HasPrefix(norm, p) {
					return true
				}
			} else if norm == p {
				return true
			}
		}
		return false
	}
	switch norm {
	case "/health", "/healthz", "/ready", "/metrics", "/login", "/register", "/auth/login", "/auth/register":
		return true
	}
	return false
}

func hasGuardMarker(content string, markers []string) bool {
	lower := strings.ToLower(content)
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

var (
	authGuardMarkers = []string{
		"useguards", "authguard", "jwtauthguard", "requireauth", "authenticate",
		"authmiddleware", "get_current_user", "login_required", "ensureauthenticated",
		"guardian", "auth_required", "verifytoken", "pipe_through :api_auth", "pipe_through [:api, :auth]",
	}
	rateLimitMarkers = []string{
		"throttle", "ratelimit", "ratelimiter", "slowapi", "plugattack", "hammer", "rate_limit",
	}
	validationMarkers = []string{
		"validationpipe", "zod", "joi", "class-validator", "pydantic", "basemodel",
		"changeset", "ecto.changeset", "shouldbindjson", "safeparse", "schema.parse", "validator",
	}
)

func parseOpenAPIPaths(doc []byte) map[string]bool {
	trimmed := bytes.TrimSpace(doc)
	if len(trimmed) == 0 {
		return nil
	}
	var parsed struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(trimmed, &parsed); err == nil && len(parsed.Paths) > 0 {
		out := make(map[string]bool, len(parsed.Paths))
		for p := range parsed.Paths {
			out[canonicalRouteTemplate(p)] = true
		}
		return out
	}
	// Minimal YAML fallback for `paths:` keys starting with `/`
	out := make(map[string]bool)
	inPaths := false
	for _, line := range strings.Split(string(trimmed), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			inPaths = strings.HasPrefix(t, "paths:")
			continue
		}
		if inPaths && indent == 2 && strings.HasPrefix(t, "/") && strings.HasSuffix(t, ":") {
			p := strings.TrimSuffix(t, ":")
			out[canonicalRouteTemplate(p)] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isValidatorOrSanitizerNode(filePath, content string) bool {
	lowerPath := strings.ToLower(filePath)
	if strings.Contains(lowerPath, "validat") || strings.Contains(lowerPath, "sanitiz") || strings.Contains(lowerPath, "schema") {
		return true
	}
	return hasGuardMarker(content, validationMarkers)
}

func sensitiveFlowSinks(sinks []string) []string {
	var out []string
	for _, s := range sinks {
		if s == "exec" || s == "db" || s == "network" {
			out = append(out, s)
		}
	}
	return out
}

func findUnvalidatedRouteToSinkPath(
	start string,
	adj map[string][]string,
	nodeByID map[string]types.GraphNode,
	normFiles map[string]string,
) ([]string, []string) {
	type item struct {
		node string
		path []string
	}
	visited := map[string]bool{start: true}
	queue := []item{{node: start, path: []string{start}}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if len(cur.path) > 1 {
			if sinks := sensitiveFlowSinks(nodeByID[cur.node].Sinks); len(sinks) > 0 {
				return cur.path, sinks
			}
			if isValidatorOrSanitizerNode(cur.node, normFiles[cur.node]) {
				continue
			}
		}
		for _, next := range adj[cur.node] {
			if visited[next] {
				continue
			}
			visited[next] = true
			nextPath := append(append([]string{}, cur.path...), next)
			queue = append(queue, item{node: next, path: nextPath})
		}
	}
	return nil, nil
}

func buildRouteSinkSteps(r discoveredRoute, flowPath []string, sinks []string) []types.CodeFlowStep {
	steps := make([]types.CodeFlowStep, 0, len(flowPath))
	for idx, mod := range flowPath {
		step := types.CodeFlowStep{FilePath: mod, Line: 1}
		switch idx {
		case 0:
			step.Line = r.Line
			step.Kind = "source"
			step.Message = fmt.Sprintf("HTTP %s %s entry point", r.Method, r.Path)
		case len(flowPath) - 1:
			step.Kind = "sink"
			step.Message = fmt.Sprintf("Reaches %s sink in %s without validation", strings.Join(sinks, ","), mod)
		default:
			step.Kind = "propagator"
			step.Message = fmt.Sprintf("Propagates through %s", mod)
		}
		steps = append(steps, step)
	}
	return steps
}

// AnalyzeArchitectureAndRouteFlows assigns architectural layers, detects forbidden layer
// dependencies, extracts HTTP routes across TS/JS, Go, Python, and Elixir, flags
// unprotected and shadow routes, and traces Route -> Service -> Sink code flows.
func AnalyzeArchitectureAndRouteFlows(
	targetDir string,
	files map[string]string,
	srcGraph types.DependencyGraph,
	arch *types.ArchitectureRules,
	openAPIDoc []byte,
) (types.DependencyGraph, []types.SecurityFinding) {
	_ = targetDir
	normFiles := make(map[string]string, len(files))
	var sortedPaths []string
	for k, v := range files {
		clean := path.Clean(strings.TrimPrefix(filepath.ToSlash(k), "./"))
		normFiles[clean] = v
		sortedPaths = append(sortedPaths, clean)
	}
	sort.Strings(sortedPaths)

	var findings []types.SecurityFinding

	// 1. Assign layers & detect forbidden layer flows
	nodeLayer := make(map[string]string, len(srcGraph.Nodes))
	if arch != nil && len(arch.Layers) > 0 {
		for i := range srcGraph.Nodes {
			bestLayer := ""
			bestLen := -1
			for _, layer := range arch.Layers {
				for _, pref := range layer.PathPrefixes {
					cleanPref := strings.TrimPrefix(filepath.ToSlash(pref), "./")
					if strings.HasPrefix(srcGraph.Nodes[i].ID, cleanPref) && len(cleanPref) > bestLen {
						bestLen = len(cleanPref)
						bestLayer = layer.Name
					}
				}
			}
			if bestLayer != "" {
				srcGraph.Nodes[i].Layer = bestLayer
				nodeLayer[srcGraph.Nodes[i].ID] = bestLayer
			}
		}

		violationIdx := 0
		for _, e := range srcGraph.Edges {
			fromLayer := nodeLayer[e.From]
			toLayer := nodeLayer[e.To]
			if fromLayer == "" || toLayer == "" {
				continue
			}
			for _, rule := range arch.ForbiddenFlows {
				if rule.From == fromLayer && rule.To == toLayer {
					violationIdx++
					id := fmt.Sprintf("layer-violation-%d", violationIdx)
					lv := types.LayerViolation{
						ID:        id,
						FromFile:  e.From,
						ToFile:    e.To,
						FromLayer: fromLayer,
						ToLayer:   toLayer,
						Reason:    rule.Reason,
						Severity:  types.SeverityHigh,
					}
					srcGraph.LayerViolations = append(srcGraph.LayerViolations, lv)
					desc := rule.Reason
					if desc == "" {
						desc = fmt.Sprintf("Module %s (%s) imports %s (%s)", e.From, fromLayer, e.To, toLayer)
					}
					findings = append(findings, types.SecurityFinding{
						ID:          id,
						Category:    types.CategoryArchitecture,
						Tool:        "architecture-analyzer",
						Severity:    types.SeverityHigh,
						Title:       fmt.Sprintf("Forbidden layer dependency: %s -> %s", fromLayer, toLayer),
						Description: desc,
						FilePath:    e.From,
						Line:        1,
					})
				}
			}
		}
	}

	// 2. Extract routes and evaluate guards, shadow routes, and Route -> Sink CodeFlows
	openAPIPaths := parseOpenAPIPaths(openAPIDoc)
	nodeByID := make(map[string]types.GraphNode, len(srcGraph.Nodes))
	for _, n := range srcGraph.Nodes {
		nodeByID[n.ID] = n
	}
	adj := make(map[string][]string)
	for _, e := range srcGraph.Edges {
		if e.Kind == "" || e.Kind == "import" {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}

	requireAuth := arch == nil || arch.RequireAuthOnNonPublic
	requireRateLimit := arch != nil && arch.RequireRateLimitOnNonPublic
	requireValidation := arch != nil && arch.RequireValidationOnMutating

	routeFindingIdx := 0
	flowFindingIdx := 0
	for _, filePath := range sortedPaths {
		content := normFiles[filePath]
		routes := extractRoutesFromFile(filePath, content)
		if len(routes) == 0 {
			continue
		}

		hasAuth := hasGuardMarker(content, authGuardMarkers)
		hasRateLimit := hasGuardMarker(content, rateLimitMarkers)
		hasValidation := hasGuardMarker(content, validationMarkers)

		for _, r := range routes {
			// Unprotected route check
			if !isPublicRoute(r.Path, arch) {
				var missing []string
				if requireAuth && !hasAuth {
					missing = append(missing, "auth")
				}
				if requireRateLimit && !hasRateLimit {
					missing = append(missing, "rate-limit")
				}
				isMutating := r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" || r.Method == "DELETE"
				if requireValidation && isMutating && !hasValidation {
					missing = append(missing, "validation")
				}
				if len(missing) > 0 {
					routeFindingIdx++
					id := fmt.Sprintf("route-unprotected-%d", routeFindingIdx)
					srcGraph.RouteFindings = append(srcGraph.RouteFindings, types.RouteGuardFinding{
						ID:            id,
						Method:        r.Method,
						Path:          r.Path,
						FilePath:      r.FilePath,
						Line:          r.Line,
						Kind:          "unprotected-route",
						MissingGuards: missing,
						Severity:      types.SeverityHigh,
					})
					findings = append(findings, types.SecurityFinding{
						ID:          id,
						Category:    types.CategoryArchitecture,
						Tool:        "route-flow-analyzer",
						Severity:    types.SeverityHigh,
						Title:       fmt.Sprintf("Unprotected route %s %s missing %s", r.Method, r.Path, strings.Join(missing, ", ")),
						Description: fmt.Sprintf("Route %s %s in %s lacks required guards: %s", r.Method, r.Path, r.FilePath, strings.Join(missing, ", ")),
						FilePath:    r.FilePath,
						Line:        r.Line,
						Endpoint:    r.Method + " " + r.Path,
					})
				}
			}

			// Shadow route check
			if len(openAPIPaths) > 0 && !openAPIPaths[canonicalRouteTemplate(r.Path)] {
				routeFindingIdx++
				id := fmt.Sprintf("route-shadow-%d", routeFindingIdx)
				srcGraph.RouteFindings = append(srcGraph.RouteFindings, types.RouteGuardFinding{
					ID:       id,
					Method:   r.Method,
					Path:     r.Path,
					FilePath: r.FilePath,
					Line:     r.Line,
					Kind:     "shadow-route",
					Severity: types.SeverityMedium,
				})
				findings = append(findings, types.SecurityFinding{
					ID:          id,
					Category:    types.CategoryArchitecture,
					Tool:        "route-flow-analyzer",
					Severity:    types.SeverityMedium,
					Title:       fmt.Sprintf("Shadow route %s %s absent from OpenAPI spec", r.Method, r.Path),
					Description: fmt.Sprintf("Route %s %s declared in %s is not documented in OpenAPI paths", r.Method, r.Path, r.FilePath),
					FilePath:    r.FilePath,
					Line:        r.Line,
					Endpoint:    r.Method + " " + r.Path,
				})
			}

			// Route -> Service -> Sink CodeFlow check
			if !hasValidation {
				flowPath, sinks := findUnvalidatedRouteToSinkPath(filePath, adj, nodeByID, normFiles)
				if len(flowPath) >= 2 {
					flowFindingIdx++
					steps := buildRouteSinkSteps(r, flowPath, sinks)
					findings = append(findings, types.SecurityFinding{
						ID:          fmt.Sprintf("route-sink-flow-%d", flowFindingIdx),
						Category:    types.CategoryArchitecture,
						Tool:        "route-flow-analyzer",
						Severity:    types.SeverityHigh,
						Title:       fmt.Sprintf("Unvalidated route %s %s reaches %s sink", r.Method, r.Path, strings.Join(sinks, ",")),
						Description: fmt.Sprintf("Flow: %s", strings.Join(flowPath, " -> ")),
						FilePath:    r.FilePath,
						Line:        r.Line,
						Endpoint:    r.Method + " " + r.Path,
						CodeFlows:   [][]types.CodeFlowStep{steps},
					})
				}
			}
		}
	}

	return srcGraph, findings
}
