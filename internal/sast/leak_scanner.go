package sast

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

var skipLeakScanDirs = map[string]bool{
	".git":                true,
	"node_modules":        true,
	"dist":                true,
	"build":               true,
	"vendor":              true,
	".worktrees":          true,
	".conformance-runner": true,
	".tsd-emit":           true,
	"coverage":            true,
	"__pycache__":         true,
	".venv":               true,
	"venv":                true,
	"_build":              true,
	"deps":                true,
	"testdata":            true,
}

// ScanStaticResourceLeaks scans source files under targetDir for compile-time
// memory and resource leak anti-patterns across Go, TypeScript/JS, Python, and Elixir.
func ScanStaticResourceLeaks(targetDir string, lang types.BoilerplateLanguage) ([]types.SecurityFinding, error) {
	if targetDir == "" {
		return nil, nil
	}
	if _, err := os.Stat(targetDir); err != nil {
		return nil, nil
	}

	if lang == "" {
		lang = detectBoilerplateLanguage(targetDir)
	}

	var findings []types.SecurityFinding
	err := filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if path != targetDir && skipLeakScanDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}

		lower := strings.ToLower(name)
		relPath := NormalizeRelativePath(path, targetDir)

		switch {
		case (lang == "" || lang == types.LangGo) && strings.HasSuffix(lower, ".go") && !strings.HasSuffix(lower, "_test.go"):
			f, scanErr := scanGoResourceLeaks(path, relPath)
			if scanErr == nil {
				findings = append(findings, f...)
			}
		case (lang == "" || lang == types.LangTypeScript || lang == types.LangJavaScript) && isTSOrJSSourceFile(lower):
			data, readErr := os.ReadFile(path)
			if readErr == nil {
				findings = append(findings, scanTSResourceLeaks(relPath, string(data))...)
			}
		case (lang == "" || lang == types.LangPython) && strings.HasSuffix(lower, ".py") && !isPythonTestFile(lower):
			data, readErr := os.ReadFile(path)
			if readErr == nil {
				findings = append(findings, scanPythonResourceLeaks(relPath, string(data))...)
			}
		case (lang == "" || lang == types.LangElixir) && isElixirSourceFile(lower):
			data, readErr := os.ReadFile(path)
			if readErr == nil {
				findings = append(findings, scanElixirResourceLeaks(relPath, string(data))...)
			}
		}
		return nil
	})
	if err != nil {
		return findings, err
	}
	return findings, nil
}

func isTSOrJSSourceFile(lowerName string) bool {
	if strings.HasSuffix(lowerName, ".d.ts") ||
		strings.HasSuffix(lowerName, ".test.ts") ||
		strings.HasSuffix(lowerName, ".spec.ts") ||
		strings.HasSuffix(lowerName, ".test.tsx") ||
		strings.HasSuffix(lowerName, ".spec.tsx") ||
		strings.HasSuffix(lowerName, ".test.js") ||
		strings.HasSuffix(lowerName, ".spec.js") ||
		strings.HasSuffix(lowerName, ".test.jsx") ||
		strings.HasSuffix(lowerName, ".spec.jsx") {
		return false
	}
	return strings.HasSuffix(lowerName, ".ts") ||
		strings.HasSuffix(lowerName, ".tsx") ||
		strings.HasSuffix(lowerName, ".js") ||
		strings.HasSuffix(lowerName, ".jsx") ||
		strings.HasSuffix(lowerName, ".mjs") ||
		strings.HasSuffix(lowerName, ".cjs")
}

func isPythonTestFile(lowerName string) bool {
	return strings.HasPrefix(lowerName, "test_") || strings.HasSuffix(lowerName, "_test.py")
}

func isElixirSourceFile(lowerName string) bool {
	if lowerName == "mix.exs" || strings.HasSuffix(lowerName, "_test.exs") {
		return false
	}
	return strings.HasSuffix(lowerName, ".ex") || strings.HasSuffix(lowerName, ".exs")
}

// Go AST leak scanner.

func scanGoResourceLeaks(path, relPath string) ([]types.SecurityFinding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}

	var findings []types.SecurityFinding

	// 1. Function-scoped checks: unclosed HTTP response bodies and SQL rows.
	ast.Inspect(file, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body != nil {
				findings = append(findings, scanGoFuncBodyLeaks(fset, relPath, fn.Body)...)
			}
		case *ast.FuncLit:
			if fn.Body != nil {
				findings = append(findings, scanGoFuncBodyLeaks(fset, relPath, fn.Body)...)
			}
		}
		return true
	})

	// 2. Loop-scoped time.After, discarded context cancel, and HTTP timeout checks.
	var walkWithLoopDepth func(node ast.Node, loopDepth int)
	walkWithLoopDepth = func(node ast.Node, loopDepth int) {
		if node == nil {
			return
		}
		switch n := node.(type) {
		case *ast.ForStmt:
			walkChildren(n, loopDepth+1, walkWithLoopDepth)
			return
		case *ast.RangeStmt:
			walkChildren(n, loopDepth+1, walkWithLoopDepth)
			return
		case *ast.FuncLit:
			// Reset loop depth inside nested closures.
			if n.Body != nil {
				walkChildren(n.Body, 0, walkWithLoopDepth)
			}
			return
		case *ast.CallExpr:
			if loopDepth > 0 && isPkgCall(n, "time", "After") {
				line := fset.Position(n.Pos()).Line
				desc := fmt.Sprintf("time.After(...) inside a loop at %s:%d allocates a new timer per iteration; use time.NewTimer or time.NewTicker with Stop().", relPath, line)
				findings = append(findings, newLeakFinding(
					"leak-go-time-after-in-loop", types.SeverityHigh,
					"time.After called inside loop", desc, relPath, line, "CWE-400",
				))
			}
		case *ast.AssignStmt:
			if f, ok := checkGoDiscardedCancel(fset, relPath, n); ok {
				findings = append(findings, f)
			}
		case *ast.CompositeLit:
			if f, ok := checkGoHTTPTimeouts(fset, relPath, n); ok {
				findings = append(findings, f)
			}
		}
		walkChildren(node, loopDepth, walkWithLoopDepth)
	}

	walkWithLoopDepth(file, 0)
	return findings, nil
}

func newLeakFinding(id string, sev types.Severity, title, desc, relPath string, line int, cwe string) types.SecurityFinding {
	return types.SecurityFinding{
		ID:          id,
		Category:    types.CategoryResourceLeak,
		Tool:        "leak-sast",
		Severity:    sev,
		Title:       title,
		Description: desc,
		FilePath:    relPath,
		Line:        line,
		CWE:         cwe,
	}
}

func checkGoDiscardedCancel(fset *token.FileSet, relPath string, stmt *ast.AssignStmt) (types.SecurityFinding, bool) {
	if len(stmt.Rhs) != 1 || len(stmt.Lhs) < 2 {
		return types.SecurityFinding{}, false
	}
	call, ok := stmt.Rhs[0].(*ast.CallExpr)
	if !ok || !isContextCancelCreator(call) {
		return types.SecurityFinding{}, false
	}
	ident, ok := stmt.Lhs[1].(*ast.Ident)
	if !ok || ident.Name != "_" {
		return types.SecurityFinding{}, false
	}
	line := fset.Position(stmt.Pos()).Line
	desc := fmt.Sprintf("Context cancel function is discarded with '_' at %s:%d, leaking context timers and goroutines.", relPath, line)
	return newLeakFinding(
		"leak-go-discarded-context-cancel", types.SeverityHigh,
		"Discarded context cancel function", desc, relPath, line, "CWE-404",
	), true
}

func checkGoHTTPTimeouts(fset *token.FileSet, relPath string, lit *ast.CompositeLit) (types.SecurityFinding, bool) {
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok {
		return types.SecurityFinding{}, false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "http" {
		return types.SecurityFinding{}, false
	}
	line := fset.Position(lit.Pos()).Line
	switch sel.Sel.Name {
	case "Server":
		if !hasKeyedField(lit, "ReadHeaderTimeout") || !hasKeyedField(lit, "IdleTimeout") {
			desc := fmt.Sprintf("http.Server literal at %s:%d omits ReadHeaderTimeout and/or IdleTimeout.", relPath, line)
			return newLeakFinding(
				"leak-go-http-missing-timeouts", types.SeverityMedium,
				"http.Server missing ReadHeaderTimeout or IdleTimeout", desc, relPath, line, "CWE-400",
			), true
		}
	case "Client":
		if !hasKeyedField(lit, "Timeout") && !hasKeyedField(lit, "Transport") {
			desc := fmt.Sprintf("http.Client literal at %s:%d sets neither Timeout nor a custom Transport.", relPath, line)
			return newLeakFinding(
				"leak-go-http-missing-timeouts", types.SeverityMedium,
				"http.Client missing Timeout", desc, relPath, line, "CWE-400",
			), true
		}
	}
	return types.SecurityFinding{}, false
}

type goTrackedVar struct {
	name string
	line int
}

func trackGoResourceAssign(fset *token.FileSet, stmt *ast.AssignStmt, httpVars, sqlRowVars *[]goTrackedVar) {
	if len(stmt.Rhs) != 1 || len(stmt.Lhs) < 1 {
		return
	}
	call, ok := stmt.Rhs[0].(*ast.CallExpr)
	if !ok {
		return
	}
	ident, ok := stmt.Lhs[0].(*ast.Ident)
	if !ok || ident.Name == "_" {
		return
	}
	line := fset.Position(stmt.Pos()).Line
	if isHTTPResponseCall(call) {
		*httpVars = append(*httpVars, goTrackedVar{name: ident.Name, line: line})
	} else if isSQLRowsCall(call) {
		*sqlRowVars = append(*sqlRowVars, goTrackedVar{name: ident.Name, line: line})
	}
}

func walkChildren(node ast.Node, loopDepth int, fn func(ast.Node, int)) {
	first := true
	ast.Inspect(node, func(child ast.Node) bool {
		if first {
			first = false
			return true
		}
		if child == nil {
			return false
		}
		fn(child, loopDepth)
		return false
	})
}

func scanGoFuncBodyLeaks(fset *token.FileSet, relPath string, body *ast.BlockStmt) []types.SecurityFinding {
	var findings []types.SecurityFinding

	// Inspect only statements belonging directly to this function body (do not descend into nested FuncLits,
	// which are scanned independently by the outer ast.Inspect).
	var httpVars []goTrackedVar
	var sqlRowVars []goTrackedVar

	bodyClosed := map[string]bool{}
	directClosed := map[string]bool{}
	returnedVars := map[string]bool{}

	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if _, isFuncLit := n.(*ast.FuncLit); isFuncLit {
			ast.Inspect(n, func(inner ast.Node) bool {
				if call, ok := inner.(*ast.CallExpr); ok {
					recordGoCloseCall(call, bodyClosed, directClosed)
				}
				return true
			})
			return false
		}

		switch stmt := n.(type) {
		case *ast.AssignStmt:
			trackGoResourceAssign(fset, stmt, &httpVars, &sqlRowVars)
		case *ast.CallExpr:
			recordGoCloseCall(stmt, bodyClosed, directClosed)
		case *ast.ReturnStmt:
			for _, res := range stmt.Results {
				if ident, ok := res.(*ast.Ident); ok {
					returnedVars[ident.Name] = true
				}
			}
		}
		return true
	})

	for _, v := range httpVars {
		if !bodyClosed[v.name] && !returnedVars[v.name] {
			desc := fmt.Sprintf("HTTP response %q assigned at %s:%d is never closed via %s.Body.Close() in the enclosing function.", v.name, relPath, v.line, v.name)
			findings = append(findings, newLeakFinding(
				"leak-go-unclosed-resp-body", types.SeverityHigh,
				fmt.Sprintf("Unclosed HTTP response body (%s.Body)", v.name), desc, relPath, v.line, "CWE-772",
			))
		}
	}

	for _, v := range sqlRowVars {
		if !directClosed[v.name] && !returnedVars[v.name] {
			desc := fmt.Sprintf("SQL rows handle %q assigned at %s:%d is never closed via %s.Close() in the enclosing function.", v.name, relPath, v.line, v.name)
			findings = append(findings, newLeakFinding(
				"leak-go-unclosed-sql-rows", types.SeverityHigh,
				fmt.Sprintf("Unclosed SQL rows (%s)", v.name), desc, relPath, v.line, "CWE-772",
			))
		}
	}

	return findings
}

func recordGoCloseCall(call *ast.CallExpr, bodyClosed, directClosed map[string]bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Close" {
		return
	}
	// Pattern 1: <var>.Body.Close()
	if innerSel, ok := sel.X.(*ast.SelectorExpr); ok && innerSel.Sel.Name == "Body" {
		if ident, ok := innerSel.X.(*ast.Ident); ok {
			bodyClosed[ident.Name] = true
		}
	}
	// Pattern 2: <var>.Close()
	if ident, ok := sel.X.(*ast.Ident); ok {
		directClosed[ident.Name] = true
	}
}

func isHTTPResponseCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "http" {
		switch sel.Sel.Name {
		case "Get", "Post", "PostForm", "Head":
			return true
		}
	}
	if sel.Sel.Name == "Do" && len(call.Args) == 1 {
		return true
	}
	return false
}

func isSQLRowsCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "Query" || sel.Sel.Name == "QueryContext"
}

func isPkgCall(call *ast.CallExpr, pkgName, funcName string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != funcName {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == pkgName
}

func isContextCancelCreator(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "context" {
		return false
	}
	switch sel.Sel.Name {
	case "WithCancel", "WithCancelCause", "WithTimeout", "WithTimeoutCause", "WithDeadline", "WithDeadlineCause":
		return true
	}
	return false
}

func hasKeyedField(lit *ast.CompositeLit, fieldName string) bool {
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == fieldName {
				return true
			}
		}
	}
	return false
}

// Line-preserving comment strippers.

func stripCStyleComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	n := len(src)
	inSingle := false
	inDouble := false
	inTemplate := false
	inLineComment := false
	inBlockComment := false

	for i := 0; i < n; i++ {
		ch := src[i]
		if inLineComment {
			if ch == '\n' {
				inLineComment = false
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		if inBlockComment {
			if ch == '*' && i+1 < n && src[i+1] == '/' {
				inBlockComment = false
				b.WriteString("  ")
				i++
			} else if ch == '\n' {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		if inSingle {
			b.WriteByte(ch)
			if ch == '\\' && i+1 < n {
				i++
				b.WriteByte(src[i])
			} else if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			b.WriteByte(ch)
			if ch == '\\' && i+1 < n {
				i++
				b.WriteByte(src[i])
			} else if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inTemplate {
			b.WriteByte(ch)
			if ch == '\\' && i+1 < n {
				i++
				b.WriteByte(src[i])
			} else if ch == '`' {
				inTemplate = false
			}
			continue
		}

		if ch == '/' && i+1 < n && src[i+1] == '/' {
			inLineComment = true
			b.WriteString("  ")
			i++
			continue
		}
		if ch == '/' && i+1 < n && src[i+1] == '*' {
			inBlockComment = true
			b.WriteString("  ")
			i++
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '`':
			inTemplate = true
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func stripHashComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	n := len(src)
	inSingle := false
	inDouble := false
	inComment := false

	for i := 0; i < n; i++ {
		ch := src[i]
		if inComment {
			if ch == '\n' {
				inComment = false
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		if inSingle {
			b.WriteByte(ch)
			if ch == '\\' && i+1 < n {
				i++
				b.WriteByte(src[i])
			} else if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			b.WriteByte(ch)
			if ch == '\\' && i+1 < n {
				i++
				b.WriteByte(src[i])
			} else if ch == '"' {
				inDouble = false
			}
			continue
		}
		if ch == '#' {
			inComment = true
			b.WriteByte(' ')
			continue
		}
		if ch == '\'' {
			inSingle = true
		} else if ch == '"' {
			inDouble = true
		}
		b.WriteByte(ch)
	}
	return b.String()
}

// TypeScript / JavaScript leak scanner.

var (
	reTSTopLevelCollection = regexp.MustCompile(
		`^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:new\s+(?:Map|Set)\b|\[\s*\])`,
	)
	reTSInterval      = regexp.MustCompile(`\bsetInterval\s*\(`)
	reTSPipe          = regexp.MustCompile(`\.pipe\s*\(`)
	reTSErrorHandler  = regexp.MustCompile(`\.on\s*\(\s*['"]error['"]`)
	reTSHandlerHeader = regexp.MustCompile(
		`\b(?:app|router|server|io|ws)\.(?:get|post|put|patch|delete|use|on)\s*\(|createServer\s*\(`,
	)
	reTSListenerOn = regexp.MustCompile(`\.on\s*\(\s*['"][^'"]+['"]`)
)

func scanTSResourceLeaks(relPath, rawSrc string) []types.SecurityFinding {
	cleaned := stripCStyleComments(rawSrc)
	lines := strings.Split(cleaned, "\n")
	var findings []types.SecurityFinding

	// 1. Unbounded top-level Map / Set / Array mutated without eviction.
	hasLRU := strings.Contains(cleaned, "LRUCache")
	if !hasLRU {
		for idx, line := range lines {
			m := reTSTopLevelCollection.FindStringSubmatch(line)
			if len(m) < 2 {
				continue
			}
			varName := m[1]
			mutated := strings.Contains(cleaned, varName+".set(") ||
				strings.Contains(cleaned, varName+".add(") ||
				strings.Contains(cleaned, varName+".push(")
			evicted := strings.Contains(cleaned, varName+".delete(") ||
				strings.Contains(cleaned, varName+".clear(") ||
				strings.Contains(cleaned, varName+".shift(") ||
				strings.Contains(cleaned, varName+".splice(") ||
				strings.Contains(cleaned, varName+".pop(") ||
				strings.Contains(cleaned, varName+".length = 0") ||
				strings.Contains(cleaned, varName+".length=0")
			if mutated && !evicted {
				lineNum := idx + 1
				findings = append(findings, types.SecurityFinding{
					ID:       "leak-ts-unbounded-module-collection",
					Category: types.CategoryResourceLeak,
					Tool:     "leak-sast",
					Severity: types.SeverityHigh,
					Title:    fmt.Sprintf("Unbounded module-level collection (%s)", varName),
					Description: fmt.Sprintf(
						"Module-level collection %q at %s:%d grows via .set/.add/.push "+
							"without .delete/.clear/.shift/.splice or an LRUCache bound.",
						varName, relPath, lineNum,
					),
					FilePath: relPath,
					Line:     lineNum,
					CWE:      "CWE-400",
				})
			}
		}
	}

	// 2. Uncleaned setInterval or .on() listener inside request/connection handler.
	hasClearInterval := strings.Contains(cleaned, "clearInterval(")
	hasListenerCleanup := strings.Contains(cleaned, ".off(") ||
		strings.Contains(cleaned, ".removeListener(") ||
		strings.Contains(cleaned, ".removeAllListeners(") ||
		strings.Contains(cleaned, ".once(")

	handlerDepth := 0
	braceDepth := 0
	inHandler := false
	for idx, line := range lines {
		lineNum := idx + 1
		if !hasClearInterval && reTSInterval.MatchString(line) {
			findings = append(findings, types.SecurityFinding{
				ID:       "leak-ts-uncleaned-interval-or-listener",
				Category: types.CategoryResourceLeak,
				Tool:     "leak-sast",
				Severity: types.SeverityMedium,
				Title:    "setInterval without clearInterval",
				Description: fmt.Sprintf(
					"setInterval() at %s:%d has no corresponding clearInterval() "+
						"in this module, leaking timers and closures.",
					relPath, lineNum,
				),
				FilePath: relPath,
				Line:     lineNum,
				CWE:      "CWE-404",
			})
		}

		if reTSHandlerHeader.MatchString(line) && !inHandler {
			inHandler = true
			handlerDepth = braceDepth
		} else if inHandler && !hasListenerCleanup && reTSListenerOn.MatchString(line) && !reTSErrorHandler.MatchString(line) {
			findings = append(findings, types.SecurityFinding{
				ID:       "leak-ts-uncleaned-interval-or-listener",
				Category: types.CategoryResourceLeak,
				Tool:     "leak-sast",
				Severity: types.SeverityMedium,
				Title:    "EventEmitter listener registered in handler without cleanup",
				Description: fmt.Sprintf(
					".on() listener registered inside a request/connection handler at %s:%d "+
						"without .off()/.removeListener()/.once().",
					relPath, lineNum,
				),
				FilePath: relPath,
				Line:     lineNum,
				CWE:      "CWE-404",
			})
		}

		braceDepth += strings.Count(line, "{") - strings.Count(line, "}")
		if inHandler && braceDepth <= handlerDepth && strings.Contains(line, "}") {
			inHandler = false
		}
	}

	// 3. Unsafe stream .pipe() without error handler or pipeline().
	hasPipeline := strings.Contains(cleaned, "pipeline(")
	hasErrorHandler := reTSErrorHandler.MatchString(cleaned)
	if !hasPipeline && !hasErrorHandler {
		for idx, line := range lines {
			if reTSPipe.MatchString(line) {
				lineNum := idx + 1
				findings = append(findings, types.SecurityFinding{
					ID:       "leak-ts-unsafe-stream-pipe",
					Category: types.CategoryResourceLeak,
					Tool:     "leak-sast",
					Severity: types.SeverityMedium,
					Title:    "Stream .pipe() without error handling or pipeline()",
					Description: fmt.Sprintf(
						"Stream .pipe() at %s:%d does not propagate errors or destroy streams "+
							"on failure; prefer stream.pipeline() or attach error handlers.",
						relPath, lineNum,
					),
					FilePath: relPath,
					Line:     lineNum,
					CWE:      "CWE-404",
				})
			}
		}
	}

	return findings
}

// Python leak scanner.

var (
	rePyUnmanagedResource = regexp.MustCompile(`\b(?:open|httpx\.Client|httpx\.AsyncClient|aiohttp\.ClientSession)\s*\(`)
	rePyUntrackedTask     = regexp.MustCompile(`^\s*asyncio\.create_task\s*\(`)
	rePyUnboundedCache    = regexp.MustCompile(
		`^\s*@(?:(?:functools\.)?lru_cache\s*\(\s*maxsize\s*=\s*None\s*\)|functools\.cache\b|cache\s*$)`,
	)
)

func scanPythonResourceLeaks(relPath, rawSrc string) []types.SecurityFinding {
	cleaned := stripHashComments(rawSrc)
	lines := strings.Split(cleaned, "\n")
	var findings []types.SecurityFinding

	hasClose := strings.Contains(cleaned, ".close(") || strings.Contains(cleaned, ".aclose(")
	lowerPath := strings.ToLower(relPath)
	isConfigModule := strings.Contains(lowerPath, "config") || strings.Contains(lowerPath, "settings")

	for idx, line := range lines {
		lineNum := idx + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// 1. Unmanaged resource outside with / async with and without .close().
		if !hasClose && rePyUnmanagedResource.MatchString(trimmed) {
			if !strings.HasPrefix(trimmed, "with ") &&
				!strings.HasPrefix(trimmed, "async with ") &&
				!strings.HasPrefix(trimmed, "return ") &&
				!strings.HasPrefix(trimmed, "def ") {
				findings = append(findings, types.SecurityFinding{
					ID:       "leak-py-unmanaged-resource",
					Category: types.CategoryResourceLeak,
					Tool:     "leak-sast",
					Severity: types.SeverityHigh,
					Title:    "Unmanaged file or HTTP client resource",
					Description: fmt.Sprintf(
						"Resource opened at %s:%d outside a 'with'/'async with' context manager "+
							"and without .close()/.aclose().",
						relPath, lineNum,
					),
					FilePath: relPath,
					Line:     lineNum,
					CWE:      "CWE-772",
				})
			}
		}

		// 2. Untracked asyncio.create_task(...) expression statement.
		if rePyUntrackedTask.MatchString(line) {
			findings = append(findings, types.SecurityFinding{
				ID:       "leak-py-untracked-async-task",
				Category: types.CategoryResourceLeak,
				Tool:     "leak-sast",
				Severity: types.SeverityMedium,
				Title:    "Untracked asyncio.create_task() reference",
				Description: fmt.Sprintf(
					"Standalone asyncio.create_task(...) at %s:%d discards the returned Task handle, "+
						"risking mid-execution GC and silent exception loss.",
					relPath, lineNum,
				),
				FilePath: relPath,
				Line:     lineNum,
				CWE:      "CWE-404",
			})
		}

		// 3. Unbounded @lru_cache(maxsize=None) or @functools.cache in non-config modules.
		if !isConfigModule && rePyUnboundedCache.MatchString(line) {
			findings = append(findings, types.SecurityFinding{
				ID:       "leak-py-unbounded-lru-cache",
				Category: types.CategoryResourceLeak,
				Tool:     "leak-sast",
				Severity: types.SeverityHigh,
				Title:    "Unbounded in-memory LRU cache decorator",
				Description: fmt.Sprintf(
					"Unbounded cache decorator at %s:%d grows memory without limit on dynamic inputs; "+
						"specify a finite maxsize.",
					relPath, lineNum,
				),
				FilePath: relPath,
				Line:     lineNum,
				CWE:      "CWE-400",
			})
		}
	}

	return findings
}

// Elixir leak scanner.

var (
	reExDynamicAtom = regexp.MustCompile(`\b(?:String|List)\.to_atom\s*\(`)
	reExBareSpawn   = regexp.MustCompile(`(^|[^\w\.])(?:spawn|spawn_link)\s*\(`)
	reExETSNew      = regexp.MustCompile(`:ets\.new\s*\(`)
)

func scanElixirResourceLeaks(relPath, rawSrc string) []types.SecurityFinding {
	cleaned := stripHashComments(rawSrc)
	lines := strings.Split(cleaned, "\n")
	var findings []types.SecurityFinding

	lowerCleaned := strings.ToLower(cleaned)
	hasETSCleanup := strings.Contains(cleaned, ":ets.delete") ||
		strings.Contains(lowerCleaned, "ttl") ||
		strings.Contains(lowerCleaned, "sweep")

	for idx, line := range lines {
		lineNum := idx + 1
		if strings.TrimSpace(line) == "" {
			continue
		}

		// 1. Dynamic atom creation (BEAM atom table is never GC'd).
		if reExDynamicAtom.MatchString(line) {
			findings = append(findings, types.SecurityFinding{
				ID:       "leak-ex-dynamic-atom-creation",
				Category: types.CategoryResourceLeak,
				Tool:     "leak-sast",
				Severity: types.SeverityCritical,
				Title:    "Dynamic atom creation exhausts BEAM atom table",
				Description: fmt.Sprintf(
					"Dynamic atom conversion at %s:%d permanently allocates BEAM atoms "+
						"that are never GC'd; use String.to_existing_atom/1.",
					relPath, lineNum,
				),
				FilePath: relPath,
				Line:     lineNum,
				CWE:      "CWE-400",
			})
		}

		// 2. Unsupervised spawn/spawn_link or unbounded :ets.new without cleanup/TTL.
		if reExBareSpawn.MatchString(line) {
			findings = append(findings, types.SecurityFinding{
				ID:       "leak-ex-unsupervised-spawn-or-ets",
				Category: types.CategoryResourceLeak,
				Tool:     "leak-sast",
				Severity: types.SeverityHigh,
				Title:    "Unsupervised bare spawn/spawn_link process",
				Description: fmt.Sprintf(
					"Bare spawn/spawn_link at %s:%d bypasses OTP supervision and can leak "+
						"zombie processes; use Task.Supervisor or DynamicSupervisor.",
					relPath, lineNum,
				),
				FilePath: relPath,
				Line:     lineNum,
				CWE:      "CWE-400",
			})
		}
		if !hasETSCleanup && reExETSNew.MatchString(line) {
			findings = append(findings, types.SecurityFinding{
				ID:       "leak-ex-unsupervised-spawn-or-ets",
				Category: types.CategoryResourceLeak,
				Tool:     "leak-sast",
				Severity: types.SeverityHigh,
				Title:    "ETS table created without deletion or TTL sweep",
				Description: fmt.Sprintf(
					":ets.new(...) at %s:%d has no :ets.delete or TTL sweep in this module, "+
						"risking unbounded off-heap memory growth.",
					relPath, lineNum,
				),
				FilePath: relPath,
				Line:     lineNum,
				CWE:      "CWE-400",
			})
		}
	}

	return findings
}
