package graph

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

type SourceGraphOptions struct {
	Language      types.BoilerplateLanguage
	GoModuleName  string
	TSBaseURL     string
	TSPathAliases map[string][]string
}

var (
	blockCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineCommentRe  = regexp.MustCompile(`(?m)//.*$`)
	hashCommentRe  = regexp.MustCompile(`(?m)#.*$`)

	tsFromImportRe    = regexp.MustCompile(`(?m)(?:import|export)\s+(?:type\s+)?(?:[^'"]*?\s+from\s+)?['"]([^'"]+)['"]`)
	tsRequireDynRe    = regexp.MustCompile(`(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	pyFromParenRe     = regexp.MustCompile(`(?ms)^\s*from\s+(\.+[A-Za-z0-9_.]*|[A-Za-z0-9_.]+)\s+import\s*\(([^)]+)\)`)
	pyFromImportRe    = regexp.MustCompile(`(?m)^\s*from\s+(\.+[A-Za-z0-9_.]*|[A-Za-z0-9_.]+)\s+import\s+([^\n#(]+)`)
	pyImportRe        = regexp.MustCompile(`(?m)^\s*import[ \t]+([A-Za-z0-9_., \t]+)`)
	exDefmoduleRe     = regexp.MustCompile(`(?m)^\s*defmodule\s+([A-Z][A-Za-z0-9_.]*)\s+do\b`)
	exMultiDirective  = regexp.MustCompile(`(?m)^\s*(?:alias|import|require|use)\s+([A-Z][A-Za-z0-9_.]*)\.\{([^}]+)\}`)
	exAliasAsRe       = regexp.MustCompile(`(?m)^\s*alias\s+([A-Z][A-Za-z0-9_.]*)\s*,\s*as:\s*([A-Z][A-Za-z0-9_]*)`)
	exSingleDirective = regexp.MustCompile(`(?m)^\s*(?:alias|import|require|use)\s+([A-Z][A-Za-z0-9_.]*)(?:\s|$|,|#|:)`)
	exRemoteCallRe    = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_.]*)\.[a-z_][A-Za-z0-9_?!]*\s*\(`)
)

var (
	nodeBuiltinMods = map[string]bool{
		"assert": true, "buffer": true, "child_process": true, "cluster": true, "console": true,
		"crypto": true, "dgram": true, "dns": true, "events": true, "fs": true, "http": true,
		"http2": true, "https": true, "module": true, "net": true, "os": true, "path": true,
		"perf_hooks": true, "process": true, "querystring": true, "readline": true, "stream": true,
		"string_decoder": true, "timers": true, "tls": true, "tty": true, "url": true, "util": true,
		"v8": true, "vm": true, "worker_threads": true, "zlib": true,
	}
	pyStdlibMods = map[string]bool{
		"__future__": true, "abc": true, "argparse": true, "array": true, "asyncio": true,
		"base64": true, "bisect": true, "builtins": true, "collections": true, "concurrent": true,
		"configparser": true, "contextlib": true, "copy": true, "csv": true, "ctypes": true,
		"dataclasses": true, "datetime": true, "decimal": true, "difflib": true, "email": true,
		"enum": true, "errno": true, "fnmatch": true, "fractions": true, "functools": true,
		"glob": true, "gzip": true, "hashlib": true, "heapq": true, "hmac": true, "html": true,
		"http": true, "importlib": true, "inspect": true, "io": true, "itertools": true,
		"json": true, "logging": true, "marshal": true, "math": true, "multiprocessing": true,
		"operator": true, "os": true, "pathlib": true, "pickle": true, "pkgutil": true,
		"platform": true, "pprint": true, "queue": true, "random": true, "re": true, "runpy": true,
		"secrets": true, "select": true, "selectors": true, "shelve": true, "shutil": true,
		"signal": true, "site": true, "socket": true, "sqlite3": true, "ssl": true, "statistics": true,
		"string": true, "struct": true, "subprocess": true, "sys": true, "sysconfig": true,
		"tarfile": true, "tempfile": true, "textwrap": true, "threading": true, "time": true,
		"traceback": true, "types": true, "typing": true, "unittest": true, "urllib": true,
		"uuid": true, "warnings": true, "weakref": true, "webbrowser": true, "xml": true, "zipfile": true,
	}
	elixirStdlibMods = map[string]bool{
		"Access": true, "Agent": true, "Application": true, "Atom": true, "Base": true,
		"Behaviour": true, "Bitwise": true, "Calendar": true, "Code": true, "Collectable": true,
		"Date": true, "DateTime": true, "DynamicSupervisor": true, "Enum": true, "Enumerable": true,
		"Exception": true, "ExUnit": true, "File": true, "Float": true, "GenServer": true,
		"IO": true, "Inspect": true, "Integer": true, "Kernel": true, "Keyword": true,
		"List": true, "Logger": true, "Macro": true, "Map": true, "MapSet": true, "Mix": true,
		"Module": true, "NaiveDateTime": true, "Node": true, "OptionParser": true, "Path": true,
		"Port": true, "Process": true, "Protocol": true, "Range": true, "Record": true,
		"Regex": true, "Registry": true, "Stream": true, "String": true, "Supervisor": true,
		"System": true, "Task": true, "Time": true, "Tuple": true, "URI": true, "Version": true,
	}
)

func DetectSinkCategories(filePath string, content string) []string {
	lowerPath := strings.ToLower(filePath)
	lowerContent := strings.ToLower(content)
	var sinks []string
	addSink := func(s string) {
		if !slices.Contains(sinks, s) {
			sinks = append(sinks, s)
		}
	}

	if strings.Contains(lowerPath, "auth") || strings.Contains(lowerPath, "jwt") || strings.Contains(lowerPath, "session") ||
		strings.Contains(lowerContent, "jsonwebtoken") || strings.Contains(lowerContent, "joken") || strings.Contains(lowerContent, "guardian") {
		addSink("auth")
	}
	if strings.Contains(lowerPath, "crypto") || strings.Contains(lowerContent, "node:crypto") || strings.Contains(lowerContent, "crypto/") || strings.Contains(lowerContent, "bcrypt") || strings.Contains(lowerContent, "argon2") {
		addSink("crypto")
	}
	if strings.Contains(lowerPath, "repo") || strings.Contains(lowerPath, "db") || strings.Contains(lowerPath, "model") ||
		strings.Contains(lowerContent, "prisma") || strings.Contains(lowerContent, "typeorm") || strings.Contains(lowerContent, "sqlalchemy") || strings.Contains(lowerContent, "ecto.repo") || strings.Contains(lowerContent, "database/sql") {
		addSink("db")
	}
	if strings.Contains(lowerContent, "child_process") || strings.Contains(lowerContent, "os/exec") || strings.Contains(lowerContent, "subprocess") || strings.Contains(lowerContent, "system.cmd") {
		addSink("exec")
	}
	if strings.Contains(lowerContent, "net/http") || strings.Contains(lowerContent, "fetch(") || strings.Contains(lowerContent, "axios") || strings.Contains(lowerContent, "req.") || strings.Contains(lowerContent, "httpx") {
		addSink("network")
	}
	return sinks
}

func BuildSourceGraphFromFiles(files map[string]string, opts SourceGraphOptions) types.DependencyGraph {
	normFiles := make(map[string]string, len(files))
	var sortedPaths []string
	for k, v := range files {
		clean := path.Clean(strings.TrimPrefix(filepath.ToSlash(k), "./"))
		normFiles[clean] = v
		sortedPaths = append(sortedPaths, clean)
	}
	sort.Strings(sortedPaths)

	nodes := make([]types.GraphNode, 0, len(sortedPaths))
	for _, p := range sortedPaths {
		nodes = append(nodes, types.GraphNode{
			ID:    p,
			Label: p,
			Type:  "module",
			Sinks: DetectSinkCategories(p, normFiles[p]),
		})
	}

	edgeSet := make(map[string]types.GraphEdge)
	addEdge := func(from, to, kind string) {
		if from == "" || to == "" || from == to {
			return
		}
		if _, ok := normFiles[to]; !ok {
			return
		}
		key := from + "->" + to
		if _, exists := edgeSet[key]; !exists {
			edgeSet[key] = types.GraphEdge{From: from, To: to, Kind: kind}
		}
	}

	extImports := make(map[string]map[string]bool)
	addExternal := func(from, pkg string) {
		pkg = strings.TrimSpace(pkg)
		if from == "" || pkg == "" {
			return
		}
		if extImports[from] == nil {
			extImports[from] = make(map[string]bool)
		}
		extImports[from][pkg] = true
	}

	switch opts.Language {
	case types.LangTypeScript, types.LangJavaScript:
		buildTSGraph(normFiles, sortedPaths, opts.TSBaseURL, opts.TSPathAliases, addEdge, addExternal)
	case types.LangGo:
		buildGoGraph(normFiles, sortedPaths, opts.GoModuleName, addEdge, addExternal)
	case types.LangPython:
		buildPythonGraph(normFiles, sortedPaths, addEdge, addExternal)
	case types.LangElixir:
		buildElixirGraph(normFiles, sortedPaths, addEdge, addExternal)
	}

	for i := range nodes {
		if exts := extImports[nodes[i].ID]; len(exts) > 0 {
			list := make([]string, 0, len(exts))
			for p := range exts {
				list = append(list, p)
			}
			sort.Strings(list)
			nodes[i].ExternalImports = list
		}
	}

	edges := make([]types.GraphEdge, 0, len(edgeSet))
	for _, e := range edgeSet {
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})

	return types.DependencyGraph{
		Nodes: nodes,
		Edges: edges,
	}
}

func resolveTSSpecifier(fromFile, spec string, files map[string]string, baseURL string, aliases map[string][]string) string {
	var candidates []string
	cleanBase := strings.TrimPrefix(path.Clean(baseURL), "./")
	if cleanBase == "." {
		cleanBase = ""
	}

	for pattern, replacements := range aliases {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(spec, prefix) {
			rest := strings.TrimPrefix(spec, prefix)
			for _, repl := range replacements {
				replPrefix := strings.TrimSuffix(repl, "*")
				direct := strings.TrimPrefix(path.Clean(replPrefix+rest), "./")
				candidates = append(candidates, direct)
				if cleanBase != "" && !strings.HasPrefix(direct, cleanBase+"/") && direct != cleanBase {
					candidates = append(candidates, path.Clean(path.Join(cleanBase, direct)))
				}
			}
		}
	}

	if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") {
		dir := path.Dir(fromFile)
		candidates = append(candidates, path.Clean(path.Join(dir, spec)))
	} else if cleanBase != "" {
		candidates = append(candidates, path.Clean(path.Join(cleanBase, spec)))
	}

	tsExts := []string{".ts", ".tsx", ".js", ".mjs", ".cjs"}
	for _, cand := range candidates {
		if _, ok := files[cand]; ok {
			return cand
		}
		// NodeNext .js/.jsx -> .ts/.tsx
		for _, jsExt := range []string{".js", ".jsx", ".mjs", ".cjs"} {
			if strings.HasSuffix(cand, jsExt) {
				stem := strings.TrimSuffix(cand, jsExt)
				for _, ext := range tsExts {
					if _, ok := files[stem+ext]; ok {
						return stem + ext
					}
				}
			}
		}
		for _, ext := range tsExts {
			if _, ok := files[cand+ext]; ok {
				return cand + ext
			}
		}
		for _, ext := range tsExts {
			idx := path.Join(cand, "index"+ext)
			if _, ok := files[idx]; ok {
				return idx
			}
		}
	}
	return ""
}

func normalizeNPMPackageName(spec string) string {
	s := strings.TrimSpace(spec)
	if s == "" || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "node:") {
		return ""
	}
	if strings.HasPrefix(s, "@") {
		parts := strings.SplitN(s, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return ""
	}
	pkg := strings.SplitN(s, "/", 2)[0]
	if nodeBuiltinMods[pkg] {
		return ""
	}
	return pkg
}

func buildTSGraph(
	files map[string]string,
	sortedPaths []string,
	baseURL string,
	aliases map[string][]string,
	addEdge func(from, to, kind string),
	addExternal func(from, pkg string),
) {
	for _, filePath := range sortedPaths {
		src := blockCommentRe.ReplaceAllString(files[filePath], "")
		src = lineCommentRe.ReplaceAllString(src, "")
		var specs []string
		for _, m := range tsFromImportRe.FindAllStringSubmatch(src, -1) {
			specs = append(specs, m[1])
		}
		for _, m := range tsRequireDynRe.FindAllStringSubmatch(src, -1) {
			specs = append(specs, m[1])
		}
		for _, s := range specs {
			if target := resolveTSSpecifier(filePath, s, files, baseURL, aliases); target != "" {
				addEdge(filePath, target, "import")
			} else if pkg := normalizeNPMPackageName(s); pkg != "" {
				addExternal(filePath, pkg)
			}
		}
	}
}

func buildGoGraph(
	files map[string]string,
	sortedPaths []string,
	goModule string,
	addEdge func(from, to, kind string),
	addExternal func(from, pkg string),
) {
	pkgToFiles := make(map[string][]string)
	for _, p := range sortedPaths {
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			continue
		}
		dir := path.Dir(p)
		if dir == "." {
			dir = ""
		}
		pkgToFiles[dir] = append(pkgToFiles[dir], p)
	}

	modPrefix := strings.TrimRight(goModule, "/")
	fset := token.NewFileSet()
	for _, p := range sortedPaths {
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, files[p], parser.ImportsOnly)
		if err != nil {
			continue
		}
		fromDir := path.Dir(p)
		if fromDir == "." {
			fromDir = ""
		}
		for _, imp := range f.Imports {
			impPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			var relPkg string
			if modPrefix != "" && strings.HasPrefix(impPath, modPrefix+"/") {
				relPkg = strings.TrimPrefix(impPath, modPrefix+"/")
			} else if modPrefix != "" && impPath == modPrefix {
				relPkg = ""
			} else {
				firstSeg := strings.SplitN(impPath, "/", 2)[0]
				if strings.Contains(firstSeg, ".") {
					addExternal(p, impPath)
				}
				continue
			}
			if relPkg == fromDir {
				continue
			}
			for _, targetFile := range pkgToFiles[relPkg] {
				addEdge(p, targetFile, "import")
			}
		}
	}
}

func resolvePyModule(basePath string, files map[string]string) string {
	clean := path.Clean(strings.TrimPrefix(basePath, "/"))
	if clean == "." || clean == "" {
		return ""
	}
	candidates := []string{clean}
	if !strings.HasPrefix(clean, "src/") {
		candidates = append(candidates, path.Join("src", clean))
	}
	for _, c := range candidates {
		if _, ok := files[c+".py"]; ok {
			return c + ".py"
		}
		initFile := path.Join(c, "__init__.py")
		if _, ok := files[initFile]; ok {
			return initFile
		}
	}
	return ""
}

func buildPythonGraph(
	files map[string]string,
	sortedPaths []string,
	addEdge func(from, to, kind string),
	addExternal func(from, pkg string),
) {
	for _, filePath := range sortedPaths {
		if !strings.HasSuffix(filePath, ".py") {
			continue
		}
		src := hashCommentRe.ReplaceAllString(files[filePath], "")
		curDir := path.Dir(filePath)

		fromMatches := append(pyFromParenRe.FindAllStringSubmatch(src, -1), pyFromImportRe.FindAllStringSubmatch(src, -1)...)
		for _, m := range fromMatches {
			modSpec := strings.TrimSpace(m[1])
			namesPart := strings.TrimSpace(m[2])
			isRelative := strings.HasPrefix(modSpec, ".")
			var baseDir string
			if isRelative {
				dots := 0
				for dots < len(modSpec) && modSpec[dots] == '.' {
					dots++
				}
				rem := strings.ReplaceAll(modSpec[dots:], ".", "/")
				anc := curDir
				for i := 1; i < dots; i++ {
					anc = path.Dir(anc)
				}
				baseDir = path.Join(anc, rem)
			} else {
				baseDir = strings.ReplaceAll(modSpec, ".", "/")
			}

			resolvedAny := false
			for _, rawSym := range strings.Split(namesPart, ",") {
				sym := strings.TrimSpace(strings.Split(strings.TrimSpace(rawSym), " ")[0])
				if sym != "" && sym != "*" {
					if target := resolvePyModule(path.Join(baseDir, sym), files); target != "" {
						addEdge(filePath, target, "import")
						resolvedAny = true
						continue
					}
				}
				if target := resolvePyModule(baseDir, files); target != "" {
					addEdge(filePath, target, "import")
					resolvedAny = true
				}
			}
			if !resolvedAny && !isRelative {
				topPkg := strings.SplitN(modSpec, ".", 2)[0]
				if topPkg != "" && !pyStdlibMods[topPkg] {
					addExternal(filePath, topPkg)
				}
			}
		}

		for _, m := range pyImportRe.FindAllStringSubmatch(src, -1) {
			for _, rawMod := range strings.Split(m[1], ",") {
				modName := strings.TrimSpace(strings.Split(strings.TrimSpace(rawMod), " ")[0])
				if modName == "" {
					continue
				}
				if target := resolvePyModule(strings.ReplaceAll(modName, ".", "/"), files); target != "" {
					addEdge(filePath, target, "import")
				} else {
					topPkg := strings.SplitN(modName, ".", 2)[0]
					if topPkg != "" && !pyStdlibMods[topPkg] {
						addExternal(filePath, topPkg)
					}
				}
			}
		}
	}
}

func camelToSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func elixirExternalPkg(modName string) string {
	root := strings.SplitN(strings.TrimSpace(modName), ".", 2)[0]
	if root == "" || elixirStdlibMods[root] {
		return ""
	}
	return camelToSnake(root)
}

func expandElixirAlias(modName string, aliases map[string]string) string {
	if target, ok := aliases[modName]; ok {
		return target
	}
	if dot := strings.Index(modName, "."); dot > 0 {
		head := modName[:dot]
		if target, ok := aliases[head]; ok {
			return target + modName[dot:]
		}
	}
	return modName
}

func buildElixirGraph(
	files map[string]string,
	sortedPaths []string,
	addEdge func(from, to, kind string),
	addExternal func(from, pkg string),
) {
	modToFile := make(map[string]string)
	for _, filePath := range sortedPaths {
		if !strings.HasSuffix(filePath, ".ex") && !strings.HasSuffix(filePath, ".exs") {
			continue
		}
		src := hashCommentRe.ReplaceAllString(files[filePath], "")
		for _, m := range exDefmoduleRe.FindAllStringSubmatch(src, -1) {
			modToFile[strings.TrimSpace(m[1])] = filePath
		}
	}

	for _, filePath := range sortedPaths {
		if !strings.HasSuffix(filePath, ".ex") && !strings.HasSuffix(filePath, ".exs") {
			continue
		}
		src := hashCommentRe.ReplaceAllString(files[filePath], "")
		fileAliases := make(map[string]string)

		for _, m := range exAliasAsRe.FindAllStringSubmatch(src, -1) {
			fullMod := strings.TrimSpace(m[1])
			shortName := strings.TrimSpace(m[2])
			if fullMod != "" && shortName != "" {
				fileAliases[shortName] = fullMod
			}
		}

		for _, m := range exMultiDirective.FindAllStringSubmatch(src, -1) {
			prefix := strings.TrimSpace(m[1])
			for _, part := range strings.Split(m[2], ",") {
				sub := strings.TrimSpace(part)
				if sub == "" {
					continue
				}
				fullMod := prefix + "." + sub
				parts := strings.Split(fullMod, ".")
				fileAliases[parts[len(parts)-1]] = fullMod
				if target, ok := modToFile[fullMod]; ok {
					addEdge(filePath, target, "import")
				} else if pkg := elixirExternalPkg(fullMod); pkg != "" {
					addExternal(filePath, pkg)
				}
			}
		}

		for _, m := range exSingleDirective.FindAllStringSubmatch(src, -1) {
			modName := strings.TrimSpace(m[1])
			parts := strings.Split(modName, ".")
			if len(parts) > 1 {
				if _, already := fileAliases[parts[len(parts)-1]]; !already {
					fileAliases[parts[len(parts)-1]] = modName
				}
			}
			if target, ok := modToFile[modName]; ok {
				addEdge(filePath, target, "import")
			} else if pkg := elixirExternalPkg(modName); pkg != "" {
				addExternal(filePath, pkg)
			}
		}

		for _, m := range exRemoteCallRe.FindAllStringSubmatch(src, -1) {
			rawMod := strings.TrimSpace(m[1])
			modName := expandElixirAlias(rawMod, fileAliases)
			if target, ok := modToFile[modName]; ok {
				addEdge(filePath, target, "import")
			} else if pkg := elixirExternalPkg(modName); pkg != "" {
				addExternal(filePath, pkg)
			}
		}
	}
}

// StripJSONC strips // line comments, /* */ block comments, and trailing commas before
// } or ] strictly outside JSON string literals.
func StripJSONC(raw []byte) []byte {
	noComments := make([]byte, 0, len(raw))
	inString := false
	escaped := false

	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if inString {
			noComments = append(noComments, ch)
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '"' {
			inString = true
			noComments = append(noComments, ch)
			continue
		}
		if ch == '/' && i+1 < len(raw) && raw[i+1] == '/' {
			i += 2
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			if i < len(raw) {
				noComments = append(noComments, '\n')
			}
			continue
		}
		if ch == '/' && i+1 < len(raw) && raw[i+1] == '*' {
			i += 2
			for i+1 < len(raw) && !(raw[i] == '*' && raw[i+1] == '/') {
				if raw[i] == '\n' {
					noComments = append(noComments, '\n')
				}
				i++
			}
			i++ // skip '/'
			continue
		}
		noComments = append(noComments, ch)
	}

	out := make([]byte, 0, len(noComments))
	inString = false
	escaped = false
	for i := 0; i < len(noComments); i++ {
		ch := noComments[i]
		if inString {
			out = append(out, ch)
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '"' {
			inString = true
			out = append(out, ch)
			continue
		}
		if ch == ',' {
			j := i + 1
			for j < len(noComments) && (noComments[j] == ' ' || noComments[j] == '\t' || noComments[j] == '\r' || noComments[j] == '\n') {
				j++
			}
			if j < len(noComments) && (noComments[j] == '}' || noComments[j] == ']') {
				continue
			}
		}
		out = append(out, ch)
	}
	return out
}

func loadTSConfigFile(targetDir, cfgPath string, visited map[string]bool) (string, map[string][]string) {
	absPath, err := filepath.Abs(cfgPath)
	if err != nil {
		absPath = filepath.Clean(cfgPath)
	}
	if visited[absPath] {
		return "", nil
	}
	visited[absPath] = true

	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", nil
	}

	var parsed struct {
		Extends         json.RawMessage `json:"extends"`
		CompilerOptions struct {
			BaseURL string              `json:"baseUrl"`
			Paths   map[string][]string `json:"paths"`
		} `json:"compilerOptions"`
	}
	if err := json.Unmarshal(StripJSONC(b), &parsed); err != nil {
		return "", nil
	}

	var extendsList []string
	if len(parsed.Extends) > 0 {
		var single string
		if err := json.Unmarshal(parsed.Extends, &single); err == nil && single != "" {
			extendsList = []string{single}
		} else {
			_ = json.Unmarshal(parsed.Extends, &extendsList)
		}
	}

	mergedBase := ""
	mergedPaths := make(map[string][]string)
	for _, ext := range extendsList {
		ext = strings.TrimSpace(ext)
		if ext == "" {
			continue
		}
		var parentPath string
		if strings.HasPrefix(ext, "./") || strings.HasPrefix(ext, "../") {
			parentPath = filepath.Join(filepath.Dir(cfgPath), ext)
		} else {
			// Ignore missing node_modules base configs without dropping local options
			cand := filepath.Join(targetDir, "node_modules", ext)
			if _, statErr := os.Stat(cand); statErr == nil {
				parentPath = cand
			} else if _, statErr := os.Stat(cand + ".json"); statErr == nil {
				parentPath = cand + ".json"
			} else {
				continue
			}
		}
		if info, statErr := os.Stat(parentPath); statErr != nil {
			if _, jsonErr := os.Stat(parentPath + ".json"); jsonErr == nil {
				parentPath = parentPath + ".json"
			} else {
				continue
			}
		} else if info.IsDir() {
			parentPath = filepath.Join(parentPath, "tsconfig.json")
		}
		pBase, pPaths := loadTSConfigFile(targetDir, parentPath, visited)
		if pBase != "" {
			mergedBase = pBase
		}
		for k, v := range pPaths {
			mergedPaths[k] = append([]string{}, v...)
		}
	}

	if parsed.CompilerOptions.BaseURL != "" {
		relDir, relErr := filepath.Rel(targetDir, filepath.Dir(cfgPath))
		if relErr != nil {
			relDir = "."
		}
		joined := path.Clean(path.Join(filepath.ToSlash(relDir), parsed.CompilerOptions.BaseURL))
		joined = strings.TrimPrefix(joined, "./")
		if joined == "." {
			joined = ""
		}
		mergedBase = joined
	}
	for k, v := range parsed.CompilerOptions.Paths {
		mergedPaths[k] = append([]string{}, v...)
	}

	if len(mergedPaths) == 0 {
		mergedPaths = nil
	}
	return mergedBase, mergedPaths
}

// LoadTSConfigChain loads tsconfig.json from targetDir using JSONC stripping, follows
// relative extends chains with cycle detection, and ignores missing node_modules bases.
func LoadTSConfigChain(targetDir string) (baseURL string, paths map[string][]string) {
	return loadTSConfigFile(targetDir, filepath.Join(targetDir, "tsconfig.json"), make(map[string]bool))
}

func parseGoModName(targetDir string) string {
	b, err := os.ReadFile(filepath.Join(targetDir, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

func shouldIncludeSourceFile(relPath string, lang types.BoilerplateLanguage) bool {
	lower := strings.ToLower(relPath)
	ext := strings.ToLower(filepath.Ext(relPath))
	switch lang {
	case types.LangTypeScript, types.LangJavaScript:
		for _, suffix := range []string{
			".d.ts", ".spec.ts", ".test.ts", ".test-d.ts",
			".spec.tsx", ".test.tsx", ".spec.js", ".test.js",
			".spec.mjs", ".test.mjs",
		} {
			if strings.HasSuffix(lower, suffix) {
				return false
			}
		}
		return ext == ".ts" || ext == ".tsx" || ext == ".js" || ext == ".mjs" || ext == ".cjs"
	case types.LangGo:
		return ext == ".go" && !strings.HasSuffix(relPath, "_test.go")
	case types.LangPython:
		return ext == ".py"
	case types.LangElixir:
		return ext == ".ex" || ext == ".exs"
	default:
		return false
	}
}

func BuildSourceGraphFromDir(targetDir string, lang types.BoilerplateLanguage) (types.DependencyGraph, error) {
	files := make(map[string]string)
	skipDirs := map[string]bool{
		".git": true, "node_modules": true, "dist": true, "build": true,
		"vendor": true, "_build": true, "deps": true, ".venv": true, "venv": true, "__pycache__": true,
		"coverage": true, "reports": true, "test": true, "tests": true, "__tests__": true,
		"evals": true, "jest": true, "scripts": true,
	}

	err := filepath.WalkDir(targetDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != targetDir && ((d.Name() != "." && strings.HasPrefix(d.Name(), ".")) || skipDirs[d.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(targetDir, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !shouldIncludeSourceFile(rel, lang) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		files[rel] = string(b)
		return nil
	})
	if err != nil {
		return types.DependencyGraph{}, err
	}

	tsBaseURL, tsPaths := LoadTSConfigChain(targetDir)
	return BuildSourceGraphFromFiles(files, SourceGraphOptions{
		Language:      lang,
		GoModuleName:  parseGoModName(targetDir),
		TSBaseURL:     tsBaseURL,
		TSPathAliases: tsPaths,
	}), nil
}
