package supplychain

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

const maxTextFileBytes = 2 * 1024 * 1024

var skippedDirs = map[string]bool{
	".git":                true,
	"node_modules":        true,
	"dist":                true,
	"build":               true,
	"_build":              true,
	"deps":                true,
	"vendor":              true,
	".venv":               true,
	"venv":                true,
	".worktrees":          true,
	".superpowers":        true,
	".conformance-runner": true,
	".tsd-emit":           true,
	"coverage":            true,
	"reports":             true,
	"test":                true,
	"tests":               true,
	"__tests__":           true,
}

var lockfileNames = map[string]bool{
	"pnpm-lock.yaml":    true,
	"package-lock.json": true,
	"yarn.lock":         true,
	"uv.lock":           true,
	"poetry.lock":       true,
	"go.sum":            true,
	"mix.lock":          true,
}

var binaryExtensions = map[string]bool{
	".png":   true,
	".jpg":   true,
	".jpeg":  true,
	".gif":   true,
	".ico":   true,
	".webp":  true,
	".woff":  true,
	".woff2": true,
	".ttf":   true,
	".eot":   true,
	".pdf":   true,
	".zip":   true,
	".tar":   true,
	".gz":    true,
	".exe":   true,
	".dll":   true,
	".so":    true,
	".dylib": true,
	".pyc":   true,
	".beam":  true,
	".wasm":  true,
}

var (
	reLongBase64       = regexp.MustCompile(`[A-Za-z0-9+/][A-Za-z0-9+/=]{239,}`)
	reHexEscapedBlob   = regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){32,}`)
	rePipeToShell      = regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|]*\|\s*(sh|bash|zsh)\b`)
	reReverseShell     = regexp.MustCompile(`(/dev/` + `tcp/|\bnc\s+(-e|-c)\b|bash\s+-i\s+>&|(?i)\bsocat\b.*EXEC:)`)
	reCredentialExfil  = regexp.MustCompile(`(\.ssh/` + `id_|\.aws/` + `credentials|/proc/` + `self/environ)`)
	reDangerousHookCmd = regexp.MustCompile(`(?i)(\bcurl\b|\bwget\b|\bnc\s+|\bbash\b|/bin/sh|child_process|\beval\s*\(|node\s+-e|python[3]?\s+-c|powershell|https?://|base64|\bexec\s*\()`)
	reSetupPyDangerous = regexp.MustCompile(`(?i)(\bsubprocess\b|\bos\.system\b|\burllib\b|\beval\s*\(|\bexec\s*\()`)
	reElixirBranchDep  = regexp.MustCompile(`branch:\s*["']([^"']+)["']`)
	reElixirHTTPDep    = regexp.MustCompile(`http://[^\s"',\]]+`)
	reGHAPullReqTarget = regexp.MustCompile(`\bpull_request_target\b`)
	reGHAPRHeadRef     = regexp.MustCompile(`github\.event\.pull_request\.head`)
	reGHAUntrustedExpr = regexp.MustCompile(`\$\{\{\s*github\.event\.(issue|pull_request|comment|discussion|head_ref|commits)[^}]*\}\}`)
	reGHAUses          = regexp.MustCompile(`^\s*-?\s*uses:\s*([^\s#]+)`)
	reTOMLQuotedString = regexp.MustCompile(`'''([^']*(?:'[^']|''[^'])*)'''|"""([^"]*)"""|'([^']*)'|"((?:\\.|[^"\\])*)"`)
)

var execSinkIndicators = []string{
	"eval(",
	"new Function",
	"vm.runIn",
	"exec(",
	"Code.eval_string",
	"child_process",
	"os/exec",
	"subprocess",
	"System.cmd",
}

// ScanRepository runs pure-Go polyglot anti-malware, Trojan-Source, lockfile integrity,
// lifecycle hook, and GitHub Actions injection checks on targetDir.
func ScanRepository(targetDir string, lang types.BoilerplateLanguage) ([]types.SecurityFinding, error) {
	if strings.TrimSpace(targetDir) == "" {
		return nil, fmt.Errorf("targetDir must not be empty")
	}
	info, err := os.Stat(targetDir)
	if err != nil {
		return nil, fmt.Errorf("stat targetDir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("targetDir is not a directory: %s", targetDir)
	}

	allowlistRegexes := loadGitleaksAllowlistPaths(targetDir)

	var findings []types.SecurityFinding

	// Source-text checks (1, 2, 3) across non-skipped, non-lockfile, non-allowlisted files.
	walkErr := filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if path != targetDir && skippedDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}
		if lockfileNames[name] {
			return nil
		}
		if binaryExtensions[strings.ToLower(filepath.Ext(name))] {
			return nil
		}

		rel, relErr := filepath.Rel(targetDir, path)
		if relErr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if isAllowlistedPath(relSlash, allowlistRegexes) {
			return nil
		}

		fi, statErr := d.Info()
		if statErr != nil || fi.Size() == 0 || fi.Size() > maxTextFileBytes {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil || bytes.IndexByte(data, 0) >= 0 {
			return nil
		}
		content := string(data)

		// Check 1: Trojan Source bidi overrides & Variation Selector steganography.
		findings = append(findings, scanTrojanSourceUnicode(relSlash, content)...)

		if !isTestSourceFile(name) {
			// Check 2: Obfuscated Base64 / hex-escaped execution droppers.
			findings = append(findings, scanObfuscatedPayloads(relSlash, content)...)

			// Check 3: Pipe-to-shell, reverse shells, and credential exfil reads.
			findings = append(findings, scanShellDropperOrExfil(relSlash, content)...)
		}

		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	// Check 4: Malicious lifecycle hooks (package.json, setup.py).
	findings = append(findings, scanLifecycleHooks(targetDir)...)

	// Check 5: Lockfile presence, integrity hashes, cleartext HTTP, and floating git deps.
	findings = append(findings, scanLockfileAndDependencyIntegrity(targetDir, lang)...)

	// Check 6: GitHub Actions workflow injection & unpinned actions.
	findings = append(findings, scanGitHubWorkflows(targetDir)...)

	return findings, nil
}

func loadGitleaksAllowlistPaths(targetDir string) []*regexp.Regexp {
	data, err := os.ReadFile(filepath.Join(targetDir, ".gitleaks.toml"))
	if err != nil {
		return nil
	}

	var patterns []*regexp.Regexp
	inAllowlist := false
	inPathsArray := false
	var pathsBuf strings.Builder

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && !inPathsArray {
			lower := strings.ToLower(line)
			inAllowlist = strings.HasPrefix(lower, "[allowlist]") || strings.HasPrefix(lower, "[[allowlists]]")
			continue
		}
		if !inAllowlist {
			continue
		}
		if !inPathsArray {
			if strings.HasPrefix(line, "paths") {
				eq := strings.Index(line, "=")
				if eq < 0 {
					continue
				}
				rhs := strings.TrimSpace(line[eq+1:])
				if strings.HasPrefix(rhs, "[") {
					pathsBuf.Reset()
					pathsBuf.WriteString(rhs)
					if hasUnquotedClosingBracket(rhs) {
						patterns = append(patterns, extractTOMLRegexList(pathsBuf.String())...)
						pathsBuf.Reset()
					} else {
						inPathsArray = true
					}
				}
			}
		} else {
			pathsBuf.WriteString("\n")
			pathsBuf.WriteString(line)
			if hasUnquotedClosingBracket(pathsBuf.String()) {
				patterns = append(patterns, extractTOMLRegexList(pathsBuf.String())...)
				pathsBuf.Reset()
				inPathsArray = false
			}
		}
	}

	return patterns
}

// hasUnquotedClosingBracket reports whether s contains a ']' character outside
// TOML string literals (''', """, ', ") and '#' line comments.
func hasUnquotedClosingBracket(s string) bool {
	for i := 0; i < len(s); {
		switch {
		case strings.HasPrefix(s[i:], "'''"):
			end := strings.Index(s[i+3:], "'''")
			if end < 0 {
				return false
			}
			i += 3 + end + 3
		case strings.HasPrefix(s[i:], `"""`):
			i += 3
			closed := false
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				if strings.HasPrefix(s[i:], `"""`) {
					i += 3
					closed = true
					break
				}
				i++
			}
			if !closed {
				return false
			}
		case s[i] == '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return false
			}
			i += 1 + end + 1
		case s[i] == '"':
			i++
			closed := false
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return false
			}
		case s[i] == '#':
			nl := strings.IndexByte(s[i:], '\n')
			if nl < 0 {
				return false
			}
			i += nl + 1
		case s[i] == ']':
			return true
		default:
			i++
		}
	}
	return false
}

func extractTOMLRegexList(raw string) []*regexp.Regexp {
	var out []*regexp.Regexp
	matches := reTOMLQuotedString.FindAllStringSubmatch(raw, -1)
	for _, m := range matches {
		var pat string
		switch {
		case m[1] != "":
			pat = m[1]
		case m[2] != "":
			pat = m[2]
		case m[3] != "":
			pat = m[3]
		case m[4] != "":
			pat = strings.ReplaceAll(m[4], `\\`, `\`)
			pat = strings.ReplaceAll(pat, `\"`, `"`)
		}
		if pat == "" {
			continue
		}
		if re, err := regexp.Compile(pat); err == nil {
			out = append(out, re)
		}
	}
	return out
}

func isAllowlistedPath(relSlash string, regexes []*regexp.Regexp) bool {
	for _, re := range regexes {
		if re.MatchString(relSlash) {
			return true
		}
	}
	return false
}

func isBidiControlRune(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

func isVariationSelectorRune(r rune) bool {
	return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF)
}

func scanTrojanSourceUnicode(relPath, content string) []types.SecurityFinding {
	var findings []types.SecurityFinding
	line := 1
	bidiReported := false
	vsReported := false
	vsRun := 0

	for _, r := range content {
		if r == '\n' {
			line++
			vsRun = 0
			continue
		}
		if !bidiReported && isBidiControlRune(r) {
			bidiReported = true
			findings = append(findings, types.SecurityFinding{
				ID:          "malware-trojan-source-unicode",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("Trojan Source bidirectional Unicode control character (U+%04X) in %s", r, relPath),
				Description: "Bidirectional override/isolate Unicode control characters (CVE-2021-42574) can disguise malicious code logic from human reviewers.",
				FilePath:    relPath,
				Line:        line,
				CWE:         "CWE-1007",
			})
		}
		if isVariationSelectorRune(r) {
			vsRun++
			if !vsReported && vsRun >= 4 {
				vsReported = true
				findings = append(findings, types.SecurityFinding{
					ID:          "malware-trojan-source-unicode",
					Category:    types.CategoryMalware,
					Tool:        "supplychain",
					Severity:    types.SeverityCritical,
					Title:       fmt.Sprintf("Invisible Unicode Variation Selector steganography run in %s", relPath),
					Description: "Detected 4 or more consecutive Unicode Variation Selector runes (U+FE00..U+FE0F or U+E0100..U+E01EF), a known steganographic malware payload technique.",
					FilePath:    relPath,
					Line:        line,
					CWE:         "CWE-506",
				})
			}
		} else {
			vsRun = 0
		}
	}

	return findings
}

func hasExecSink(content string) bool {
	for _, indicator := range execSinkIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}
	return false
}

func isBenignBase64Prefix(line string, matchStart int) bool {
	prefix := strings.ToLower(line[:matchStart])
	if strings.HasSuffix(prefix, "sha256-") ||
		strings.HasSuffix(prefix, "sha384-") ||
		strings.HasSuffix(prefix, "sha512-") ||
		strings.HasSuffix(prefix, "sha256.") ||
		strings.HasSuffix(prefix, "sha384.") ||
		strings.HasSuffix(prefix, "sha512.") {
		return true
	}
	if idx := strings.LastIndex(prefix, "data:image/"); idx >= 0 && matchStart-idx <= 64 {
		return true
	}
	return false
}

func scanObfuscatedPayloads(relPath, content string) []types.SecurityFinding {
	lines := strings.Split(content, "\n")
	matchLine := 0
	matchKind := ""

	for i, line := range lines {
		if locs := reLongBase64.FindAllStringIndex(line, -1); len(locs) > 0 {
			for _, loc := range locs {
				candidate := line[loc[0]:loc[1]]
				if strings.Count(candidate, "=") > len(candidate)/4 {
					continue
				}
				if isBenignBase64Prefix(line, loc[0]) {
					continue
				}
				matchLine = i + 1
				matchKind = "long Base64 payload"
				break
			}
		}
		if matchLine > 0 {
			break
		}
		if reHexEscapedBlob.MatchString(line) {
			matchLine = i + 1
			matchKind = "hex-escaped byte sequence"
			break
		}
	}

	if matchLine == 0 {
		return nil
	}

	if hasExecSink(content) {
		return []types.SecurityFinding{{
			ID:          "malware-obfuscated-exec-dropper",
			Category:    types.CategoryMalware,
			Tool:        "supplychain",
			Severity:    types.SeverityCritical,
			Title:       fmt.Sprintf("Obfuscated %s paired with dynamic execution in %s", matchKind, relPath),
			Description: "High-entropy encoded literal paired with eval/exec/process-spawning primitives in the same file indicates an obfuscated malware dropper.",
			FilePath:    relPath,
			Line:        matchLine,
			CWE:         "CWE-506",
		}}
	}

	return []types.SecurityFinding{{
		ID:          "supplychain-suspicious-encoded-blob",
		Category:    types.CategorySupplyChain,
		Tool:        "supplychain",
		Severity:    types.SeverityHigh,
		Title:       fmt.Sprintf("Suspicious obfuscated %s in %s", matchKind, relPath),
		Description: "Large continuous Base64 or hex-escaped literal found outside allowlisted paths or lockfiles.",
		FilePath:    relPath,
		Line:        matchLine,
		CWE:         "CWE-506",
	}}
}

func isTestSourceFile(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "test_") && strings.HasSuffix(lower, ".py") {
		return true
	}
	for _, suffix := range []string{
		"_test.go",
		"_test.py",
		"_test.exs",
		".test.ts", ".spec.ts",
		".test.tsx", ".spec.tsx",
		".test.js", ".spec.js",
		".test.jsx", ".spec.jsx",
		".test.mjs", ".spec.mjs",
		".test.cjs", ".spec.cjs",
	} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func scanShellDropperOrExfil(relPath, content string) []types.SecurityFinding {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		var reason string
		switch {
		case rePipeToShell.MatchString(line):
			reason = strings.Join([]string{"Remote script pipe-to-shell dropper (curl/wget", "sh/bash)"}, " | ")
		case reReverseShell.MatchString(line):
			reason = "Reverse shell invocation (/dev/tcp, nc " + "-e/-c, bash -i, or socat EXEC)"
		case reCredentialExfil.MatchString(line):
			reason = "Direct access to sensitive host credentials (.ssh/" + "id_, .aws/" + "credentials, or /proc/" + "self/environ)"
		}
		if reason != "" {
			return []types.SecurityFinding{{
				ID:          "malware-shell-dropper-or-exfil",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("%s in %s", reason, relPath),
				Description: fmt.Sprintf("Detected suspicious command or credential access on line %d of %s.", i+1, relPath),
				FilePath:    relPath,
				Line:        i + 1,
				CWE:         "CWE-506",
			}}
		}
	}
	return nil
}

type packageJSONDoc struct {
	Scripts              map[string]string `json:"scripts"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

func scanLifecycleHooks(targetDir string) []types.SecurityFinding {
	var findings []types.SecurityFinding

	pkgPath := filepath.Join(targetDir, "package.json")
	if data, err := os.ReadFile(pkgPath); err == nil {
		var pkg packageJSONDoc
		if json.Unmarshal(data, &pkg) == nil && len(pkg.Scripts) > 0 {
			hooks := []string{"preinstall", "install", "postinstall", "preuninstall", "postuninstall"}
			for _, hook := range hooks {
				cmd := strings.TrimSpace(pkg.Scripts[hook])
				if cmd == "" {
					continue
				}
				cat := types.CategorySupplyChain
				sev := types.SeverityHigh
				if reDangerousHookCmd.MatchString(cmd) {
					cat = types.CategoryMalware
					sev = types.SeverityCritical
				}
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-malicious-lifecycle-hook",
					Category:    cat,
					Tool:        "supplychain",
					Severity:    sev,
					Title:       fmt.Sprintf("Package lifecycle hook %q in package.json", hook),
					Description: fmt.Sprintf("Lifecycle script %q executes: %s", hook, cmd),
					FilePath:    "package.json",
					CWE:         "CWE-506",
				})
			}
		}
	}

	setupPath := filepath.Join(targetDir, "setup.py")
	if data, err := os.ReadFile(setupPath); err == nil {
		content := string(data)
		if reSetupPyDangerous.MatchString(content) {
			findings = append(findings, types.SecurityFinding{
				ID:          "supplychain-malicious-lifecycle-hook",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       "Suspicious command or network execution in Python setup.py",
				Description: "setup.py invokes subprocess, os.system, urllib, or dynamic eval/exec during package installation.",
				FilePath:    "setup.py",
				CWE:         "CWE-506",
			})
		}
	}

	return findings
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

type packageLockIntegrityDoc struct {
	Packages map[string]struct {
		Resolved  string `json:"resolved"`
		Integrity string `json:"integrity"`
		Link      bool   `json:"link"`
	} `json:"packages"`
}

func scanLockfileAndDependencyIntegrity(targetDir string, _ types.BoilerplateLanguage) []types.SecurityFinding {
	var findings []types.SecurityFinding

	// 1. Node / TypeScript (package.json + lockfiles)
	if data, err := os.ReadFile(filepath.Join(targetDir, "package.json")); err == nil {
		var pkg packageJSONDoc
		if json.Unmarshal(data, &pkg) == nil {
			hasDeps := len(pkg.Dependencies) > 0 || len(pkg.DevDependencies) > 0
			hasLock := fileExists(filepath.Join(targetDir, "pnpm-lock.yaml")) ||
				fileExists(filepath.Join(targetDir, "package-lock.json")) ||
				fileExists(filepath.Join(targetDir, "yarn.lock"))
			if hasDeps && !hasLock {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-lockfile-integrity",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       "Missing JavaScript/TypeScript lockfile (pnpm-lock.yaml, package-lock.json, or yarn.lock)",
					Description: "package.json declares dependencies without a committed lockfile to pin transitive dependency hashes.",
					FilePath:    "package.json",
					CWE:         "CWE-829",
				})
			}

			for _, depMap := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
				for depName, spec := range depMap {
					trimmed := strings.TrimSpace(spec)
					lower := strings.ToLower(trimmed)
					if strings.Contains(lower, "http://") {
						findings = append(findings, types.SecurityFinding{
							ID:          "supplychain-lockfile-integrity",
							Category:    types.CategorySupplyChain,
							Tool:        "supplychain",
							Severity:    types.SeverityHigh,
							Title:       fmt.Sprintf("Cleartext HTTP dependency URL for %q in package.json", depName),
							Description: fmt.Sprintf("Dependency %q uses insecure cleartext URL %q.", depName, trimmed),
							FilePath:    "package.json",
							PackageName: depName,
							CWE:         "CWE-494",
						})
					}
					if strings.HasSuffix(lower, "#main") || strings.HasSuffix(lower, "#master") || strings.HasSuffix(lower, "#head") {
						findings = append(findings, types.SecurityFinding{
							ID:          "supplychain-lockfile-integrity",
							Category:    types.CategorySupplyChain,
							Tool:        "supplychain",
							Severity:    types.SeverityHigh,
							Title:       fmt.Sprintf("Floating git branch dependency %q in package.json", depName),
							Description: fmt.Sprintf("Dependency %q tracks mutable git ref %q instead of a pinned tag or commit SHA.", depName, trimmed),
							FilePath:    "package.json",
							PackageName: depName,
							CWE:         "CWE-829",
						})
					}
				}
			}
		}
	}

	if data, err := os.ReadFile(filepath.Join(targetDir, "package-lock.json")); err == nil {
		var lock packageLockIntegrityDoc
		if json.Unmarshal(data, &lock) == nil {
			pkgKeys := make([]string, 0, len(lock.Packages))
			for k := range lock.Packages {
				pkgKeys = append(pkgKeys, k)
			}
			sort.Strings(pkgKeys)

			reportedMissingIntegrity := false
			for _, pkgKey := range pkgKeys {
				entry := lock.Packages[pkgKey]
				if pkgKey == "" || entry.Link || strings.TrimSpace(entry.Resolved) == "" {
					continue
				}
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(entry.Resolved)), "http://") {
					findings = append(findings, types.SecurityFinding{
						ID:          "supplychain-lockfile-integrity",
						Category:    types.CategorySupplyChain,
						Tool:        "supplychain",
						Severity:    types.SeverityHigh,
						Title:       fmt.Sprintf("Cleartext HTTP resolved URL in package-lock.json for %s", pkgKey),
						Description: fmt.Sprintf("Resolved URL %q does not use HTTPS.", entry.Resolved),
						FilePath:    "package-lock.json",
						CWE:         "CWE-494",
					})
				}
				if !reportedMissingIntegrity && strings.TrimSpace(entry.Integrity) == "" {
					reportedMissingIntegrity = true
					findings = append(findings, types.SecurityFinding{
						ID:          "supplychain-lockfile-integrity",
						Category:    types.CategorySupplyChain,
						Tool:        "supplychain",
						Severity:    types.SeverityHigh,
						Title:       fmt.Sprintf("Missing integrity hash in package-lock.json for %s", pkgKey),
						Description: "Resolved package entry in package-lock.json lacks a cryptographic integrity digest.",
						FilePath:    "package-lock.json",
						CWE:         "CWE-353",
					})
				}
			}
		}
	}

	// 2. Go (go.mod + go.sum — go.sum only required when go.mod has require directives)
	if data, err := os.ReadFile(filepath.Join(targetDir, "go.mod")); err == nil {
		if goModHasRequire(string(data)) && !fileExists(filepath.Join(targetDir, "go.sum")) {
			findings = append(findings, types.SecurityFinding{
				ID:          "supplychain-lockfile-integrity",
				Category:    types.CategorySupplyChain,
				Tool:        "supplychain",
				Severity:    types.SeverityHigh,
				Title:       "Missing go.sum lockfile for Go module with external dependencies",
				Description: "go.mod declares require directives without a corresponding go.sum checksum file.",
				FilePath:    "go.mod",
				CWE:         "CWE-829",
			})
		}
	}

	// 3. Python (pyproject.toml + uv.lock/poetry.lock)
	if data, err := os.ReadFile(filepath.Join(targetDir, "pyproject.toml")); err == nil {
		content := string(data)
		if pyprojectHasDependencies(content) {
			hasLock := fileExists(filepath.Join(targetDir, "uv.lock")) ||
				fileExists(filepath.Join(targetDir, "poetry.lock"))
			if !hasLock {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-lockfile-integrity",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       "Missing Python lockfile (uv.lock or poetry.lock)",
					Description: "pyproject.toml declares dependencies without a committed uv.lock or poetry.lock file.",
					FilePath:    "pyproject.toml",
					CWE:         "CWE-829",
				})
			}
		}
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(strings.ToLower(line), "http://") {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-lockfile-integrity",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       "Cleartext HTTP URL in pyproject.toml",
					Description: fmt.Sprintf("Line %d of pyproject.toml contains an insecure cleartext http:// URL.", i+1),
					FilePath:    "pyproject.toml",
					Line:        i + 1,
					CWE:         "CWE-494",
				})
			}
		}
	}

	// 4. Elixir (mix.exs + mix.lock)
	if data, err := os.ReadFile(filepath.Join(targetDir, "mix.exs")); err == nil {
		content := string(data)
		if strings.Contains(content, "defp deps") || strings.Contains(content, "def deps") {
			if !fileExists(filepath.Join(targetDir, "mix.lock")) {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-lockfile-integrity",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       "Missing Elixir mix.lock lockfile",
					Description: "mix.exs declares dependencies without a committed mix.lock file.",
					FilePath:    "mix.exs",
					CWE:         "CWE-829",
				})
			}
		}
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if reElixirHTTPDep.MatchString(line) {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-lockfile-integrity",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       "Cleartext HTTP dependency URL in mix.exs",
					Description: fmt.Sprintf("Line %d of mix.exs references an insecure http:// URL.", i+1),
					FilePath:    "mix.exs",
					Line:        i + 1,
					CWE:         "CWE-494",
				})
			}
			if m := reElixirBranchDep.FindStringSubmatch(line); len(m) > 1 {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-lockfile-integrity",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("Floating git branch dependency (branch: %q) in mix.exs", m[1]),
					Description: "Git dependencies in mix.exs must be pinned to an immutable tag or commit ref rather than a mutable branch.",
					FilePath:    "mix.exs",
					Line:        i + 1,
					CWE:         "CWE-829",
				})
			}
		}
	}

	return findings
}

func goModHasRequire(content string) bool {
	inRequireBlock := false
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		if inRequireBlock {
			if line == ")" {
				inRequireBlock = false
				continue
			}
			return true
		}
		if strings.HasPrefix(line, "require (") || line == "require(" {
			inRequireBlock = true
			continue
		}
		if strings.HasPrefix(line, "require ") && !strings.HasSuffix(line, "(") {
			return true
		}
	}
	return false
}

func pyprojectHasDependencies(content string) bool {
	inDepsArray := false
	inPoetryDeps := false
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && !inDepsArray {
			inPoetryDeps = strings.EqualFold(line, "[tool.poetry.dependencies]")
			continue
		}
		if inPoetryDeps {
			if strings.Contains(line, "=") && !strings.HasPrefix(strings.ToLower(line), "python") {
				return true
			}
		}
		if !inDepsArray && strings.HasPrefix(line, "dependencies") {
			eq := strings.Index(line, "=")
			if eq < 0 {
				continue
			}
			rhs := strings.TrimSpace(line[eq+1:])
			if strings.HasPrefix(rhs, "[") {
				if strings.Contains(rhs, "]") {
					inner := strings.TrimSpace(rhs[1:strings.Index(rhs, "]")])
					if inner != "" {
						return true
					}
				} else {
					inDepsArray = true
				}
			}
		} else if inDepsArray {
			if strings.HasPrefix(line, "]") {
				inDepsArray = false
				continue
			}
			if strings.ContainsAny(line, `"'`) {
				return true
			}
		}
	}
	return false
}

func scanGitHubWorkflows(targetDir string) []types.SecurityFinding {
	wfDir := filepath.Join(targetDir, ".github", "workflows")
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		return nil
	}

	var findings []types.SecurityFinding
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		fullPath := filepath.Join(wfDir, entry.Name())
		data, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		relPath := filepath.ToSlash(filepath.Join(".github", "workflows", entry.Name()))
		content := string(data)

		// 1. pull_request_target + PR head checkout
		if reGHAPullReqTarget.MatchString(content) && reGHAPRHeadRef.MatchString(content) {
			findings = append(findings, types.SecurityFinding{
				ID:          "supplychain-github-actions-injection",
				Category:    types.CategorySupplyChain,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("Dangerous pull_request_target checkout of untrusted PR head in %s", relPath),
				Description: "Combining pull_request_target with github.event.pull_request.head executes untrusted fork code with repository write/secret privileges.",
				FilePath:    relPath,
				CWE:         "CWE-94",
			})
		}

		// 2. Untrusted ${{ github.event.* }} inside run: steps & 3. unpinned uses: @main/@master/@HEAD
		lines := strings.Split(content, "\n")
		inRunBlock := false
		runIndent := 0
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			indent := len(line) - len(strings.TrimLeft(line, " "))

			if inRunBlock && indent <= runIndent {
				inRunBlock = false
			}

			// Check uses:
			if m := reGHAUses.FindStringSubmatch(line); len(m) > 1 {
				actionRef := strings.Trim(m[1], `"'`)
				if !strings.HasPrefix(actionRef, "./") && !strings.HasPrefix(actionRef, "docker://") {
					lowerRef := strings.ToLower(actionRef)
					if strings.HasSuffix(lowerRef, "@main") || strings.HasSuffix(lowerRef, "@master") || strings.HasSuffix(lowerRef, "@head") {
						findings = append(findings, types.SecurityFinding{
							ID:          "supplychain-github-actions-injection",
							Category:    types.CategorySupplyChain,
							Tool:        "supplychain",
							Severity:    types.SeverityHigh,
							Title:       fmt.Sprintf("Unpinned mutable GitHub Action reference %q in %s", actionRef, relPath),
							Description: "Pin third-party GitHub Actions to an immutable commit SHA or version tag instead of @main/@master/@HEAD.",
							FilePath:    relPath,
							Line:        i + 1,
							CWE:         "CWE-829",
						})
					}
				}
			}

			// Check run:
			cleaned := strings.TrimPrefix(trimmed, "- ")
			cleaned = strings.TrimSpace(cleaned)
			if strings.HasPrefix(cleaned, "run:") {
				rhs := strings.TrimSpace(strings.TrimPrefix(cleaned, "run:"))
				if isYAMLBlockScalarHeader(rhs) {
					inRunBlock = true
					runIndent = indent
				} else if reGHAUntrustedExpr.MatchString(rhs) {
					findings = append(findings, types.SecurityFinding{
						ID:          "supplychain-github-actions-injection",
						Category:    types.CategorySupplyChain,
						Tool:        "supplychain",
						Severity:    types.SeverityCritical,
						Title:       fmt.Sprintf("GitHub Actions script injection via untrusted expression in %s", relPath),
						Description: fmt.Sprintf("Untrusted github.event.* expression interpolated directly into shell run step on line %d.", i+1),
						FilePath:    relPath,
						Line:        i + 1,
						CWE:         "CWE-78",
					})
				}
			} else if inRunBlock && reGHAUntrustedExpr.MatchString(line) {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-github-actions-injection",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityCritical,
					Title:       fmt.Sprintf("GitHub Actions script injection via untrusted expression in %s", relPath),
					Description: fmt.Sprintf("Untrusted github.event.* expression interpolated directly into shell run step on line %d.", i+1),
					FilePath:    relPath,
					Line:        i + 1,
					CWE:         "CWE-78",
				})
			}
		}
	}

	return findings
}

func isYAMLBlockScalarHeader(rhs string) bool {
	s := strings.TrimSpace(rhs)
	if s == "" {
		return true
	}
	if idx := strings.IndexByte(s, '#'); idx > 0 && (s[idx-1] == ' ' || s[idx-1] == '\t') {
		s = strings.TrimSpace(s[:idx])
	}
	switch s {
	case "|", ">", "|-", ">-", "|+", ">+":
		return true
	default:
		return false
	}
}
