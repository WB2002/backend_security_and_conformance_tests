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
	exSingleDirective = regexp.MustCompile(`(?m)^\s*(?:alias|import|require|use)\s+([A-Z][A-Za-z0-9_.]*)(?:\s|$|,|#|:)`)
	exRemoteCallRe    = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_.]*)\.[a-z_][A-Za-z0-9_?!]*\s*\(`)
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

	switch opts.Language {
	case types.LangTypeScript, types.LangJavaScript:
		buildTSGraph(normFiles, sortedPaths, opts.TSPathAliases, addEdge)
	case types.LangGo:
		buildGoGraph(normFiles, sortedPaths, opts.GoModuleName, addEdge)
	case types.LangPython:
		buildPythonGraph(normFiles, sortedPaths, addEdge)
	case types.LangElixir:
		buildElixirGraph(normFiles, sortedPaths, addEdge)
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

func resolveTSSpecifier(fromFile, spec string, files map[string]string, aliases map[string][]string) string {
	var candidates []string
	for pattern, replacements := range aliases {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(spec, prefix) {
			rest := strings.TrimPrefix(spec, prefix)
			for _, repl := range replacements {
				replPrefix := strings.TrimSuffix(repl, "*")
				candidates = append(candidates, path.Clean(replPrefix+rest))
			}
		}
	}

	if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") {
		dir := path.Dir(fromFile)
		candidates = append(candidates, path.Clean(path.Join(dir, spec)))
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

func buildTSGraph(files map[string]string, sortedPaths []string, aliases map[string][]string, addEdge func(from, to, kind string)) {
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
			if target := resolveTSSpecifier(filePath, s, files, aliases); target != "" {
				addEdge(filePath, target, "import")
			}
		}
	}
}

func buildGoGraph(files map[string]string, sortedPaths []string, goModule string, addEdge func(from, to, kind string)) {
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
	if _, ok := files[clean+".py"]; ok {
		return clean + ".py"
	}
	initFile := path.Join(clean, "__init__.py")
	if _, ok := files[initFile]; ok {
		return initFile
	}
	return ""
}

func buildPythonGraph(files map[string]string, sortedPaths []string, addEdge func(from, to, kind string)) {
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
			var baseDir string
			if strings.HasPrefix(modSpec, ".") {
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

			for _, rawSym := range strings.Split(namesPart, ",") {
				sym := strings.TrimSpace(strings.Split(strings.TrimSpace(rawSym), " ")[0])
				if sym != "" && sym != "*" {
					if target := resolvePyModule(path.Join(baseDir, sym), files); target != "" {
						addEdge(filePath, target, "import")
						continue
					}
				}
				if target := resolvePyModule(baseDir, files); target != "" {
					addEdge(filePath, target, "import")
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
				}
			}
		}
	}
}

func buildElixirGraph(files map[string]string, sortedPaths []string, addEdge func(from, to, kind string)) {
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

		for _, m := range exMultiDirective.FindAllStringSubmatch(src, -1) {
			prefix := strings.TrimSpace(m[1])
			for _, part := range strings.Split(m[2], ",") {
				sub := strings.TrimSpace(part)
				if sub == "" {
					continue
				}
				fullMod := prefix + "." + sub
				if target, ok := modToFile[fullMod]; ok {
					addEdge(filePath, target, "import")
				}
			}
		}

		for _, m := range exSingleDirective.FindAllStringSubmatch(src, -1) {
			modName := strings.TrimSpace(m[1])
			if target, ok := modToFile[modName]; ok {
				addEdge(filePath, target, "import")
			}
		}

		for _, m := range exRemoteCallRe.FindAllStringSubmatch(src, -1) {
			modName := strings.TrimSpace(m[1])
			if target, ok := modToFile[modName]; ok {
				addEdge(filePath, target, "import")
			}
		}
	}
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

func parseTSConfigPaths(targetDir string) map[string][]string {
	b, err := os.ReadFile(filepath.Join(targetDir, "tsconfig.json"))
	if err != nil {
		return nil
	}
	var parsed struct {
		CompilerOptions struct {
			Paths map[string][]string `json:"paths"`
		} `json:"compilerOptions"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		return nil
	}
	return parsed.CompilerOptions.Paths
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

	return BuildSourceGraphFromFiles(files, SourceGraphOptions{
		Language:      lang,
		GoModuleName:  parseGoModName(targetDir),
		TSPathAliases: parseTSConfigPaths(targetDir),
	}), nil
}
