package supplychain

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

// ScanOptions configures optional registry allowlists and online enrichment
// for ScanRepositoryWithOptions.
type ScanOptions struct {
	OnlineEnrich      bool
	AllowedRegistries []string
	HTTPClient        *http.Client
}

var defaultAllowedRegistries = []string{
	"registry.npmjs.org",
	"registry.yarnpkg.com",
	"files.pythonhosted.org",
	"pypi.org",
	"repo.hex.pm",
	"proxy.golang.org",
}

var (
	reGoGenerateDangerous = regexp.MustCompile(`(?i)\b(sh|bash|nc|python3?|powershell|curl|wget)\b`)
	reElixirNIFCompilers  = regexp.MustCompile(`compilers:\s*\[[^\]]*(:elixir_make|:rustler|:make)`)
	reMakefileDangerous   = regexp.MustCompile(`(?i)(\b(curl|wget)\b|\bnc\s+(-e|-c)\b|bash\s+-i)`)
	reTOMLURLField        = regexp.MustCompile(`(?i)\b(url|registry)\s*=\s*"([^"]+)"`)
	reHTTPURL             = regexp.MustCompile(`https?://[^\s"'<>]+`)
	reElixirDepAtom       = regexp.MustCompile(`\{\s*:([a-z][a-z0-9_]*)\s*,`)
	rePyReqName           = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)`)
	reIntegrityAlgo       = regexp.MustCompile(`(?i)\bsha(1|256|384|512)[-:][A-Za-z0-9+/=_-]+`)
	reHexSHA40            = regexp.MustCompile(`^[0-9a-f]{40}$`)
	reGHATopPermissions   = regexp.MustCompile(`(?m)^permissions:`)
	reGHAWorkflowRun      = regexp.MustCompile(`\bworkflow_run\b`)
	reGHAWorkflowRunHead  = regexp.MustCompile(`github\.event\.workflow_run\.head_(sha|branch|repository)`)
	reGHARunEnvInject     = regexp.MustCompile(`(>>\s*"?\$\{?GITHUB_(ENV|PATH)\}?|LD_PRELOAD\s*=)`)
)

var standardPythonBackends = map[string]bool{
	"setuptools.build_meta":            true,
	"setuptools.build_meta:__legacy__": true,
	"hatchling.build":                  true,
	"poetry.core.masonry.api":          true,
	"flit_core.buildapi":               true,
	"pdm.backend":                      true,
	"maturin":                          true,
	"scikit_build_core.build":          true,
	"mesonpy":                          true,
	"uv_build":                         true,
}

var curatedTopPackagesByEcosystem = map[string][]string{
	"npm": {
		"express", "fastify", "lodash", "axios", "prisma", "jsonwebtoken",
		"react", "next", "typescript", "eslint", "prettier", "zod", "helmet",
		"mongoose", "sequelize", "typeorm", "nestjs", "dotenv", "chalk",
		"commander", "webpack", "vite", "jest", "vitest", "mocha", "bcrypt",
		"bcryptjs", "passport", "socket.io", "winston", "pino", "ioredis",
		"redis", "mysql2", "nodemon", "supertest", "cors", "body-parser",
		"cookie-parser", "multer", "uuid", "dayjs", "moment", "rxjs",
		"graphql", "apollo-server", "esbuild", "rollup", "tailwindcss",
	},
	"pypi": {
		"requests", "fastapi", "pydantic", "sqlalchemy", "django", "flask",
		"uvicorn", "gunicorn", "celery", "pytest", "numpy", "pandas", "scipy",
		"httpx", "aiohttp", "alembic", "psycopg2", "pyjwt", "cryptography",
		"boto3", "click", "typer", "jinja2", "pyyaml", "pillow",
		"beautifulsoup4", "urllib3", "certifi", "setuptools", "wheel",
		"starlette", "passlib", "python-dotenv", "python-jose", "structlog",
		"loguru", "black", "ruff", "mypy",
	},
	"hex": {
		"phoenix", "ecto", "plug", "jason", "swoosh", "oban", "absinthe",
		"guardian", "tesla", "finch", "bandit", "cowboy", "postgrex",
		"myxql", "redix", "broadway", "telemetry", "credo", "dialyxir",
		"ex_doc", "timex", "gettext", "bcrypt_elixir", "argon2_elixir",
		"joken", "cors_plug",
	},
	"go": {
		"gorm", "sqlx", "gorilla", "zerolog", "logrus", "cobra", "viper",
		"testify", "protobuf", "fiber", "echo",
	},
}

var curatedTopPackagesSetByEcosystem = func() map[string]map[string]bool {
	out := make(map[string]map[string]bool, len(curatedTopPackagesByEcosystem))
	for eco, pkgs := range curatedTopPackagesByEcosystem {
		set := make(map[string]bool, len(pkgs))
		for _, p := range pkgs {
			set[p] = true
		}
		out[eco] = set
	}
	return out
}()

func buildAllowedRegistrySet(opts ScanOptions) map[string]bool {
	list := opts.AllowedRegistries
	if len(list) == 0 {
		list = defaultAllowedRegistries
	}
	allowed := make(map[string]bool, len(list))
	for _, entry := range list {
		raw := strings.TrimSpace(strings.ToLower(entry))
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "://") {
			if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
				allowed[strings.ToLower(u.Hostname())] = true
				continue
			}
		}
		if idx := strings.IndexByte(raw, '/'); idx >= 0 {
			raw = raw[:idx]
		}
		if idx := strings.IndexByte(raw, ':'); idx >= 0 {
			raw = raw[:idx]
		}
		if raw != "" {
			allowed[raw] = true
		}
	}
	return allowed
}

func isAllowedRegistryURL(rawURL string, allowed map[string]bool) (string, bool) {
	trimmed := strings.TrimSpace(rawURL)
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return "", true
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", true
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", true
	}
	return host, allowed[host]
}

type rootPackagePnpmDoc struct {
	Pnpm struct {
		OnlyBuiltDependencies *[]string `json:"onlyBuiltDependencies"`
	} `json:"pnpm"`
}

func hasInstallScriptProtection(targetDir string) bool {
	if data, err := os.ReadFile(filepath.Join(targetDir, ".npmrc")); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			eq := strings.IndexByte(line, '=')
			if eq < 0 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(line[:eq]))
			val := strings.ToLower(strings.TrimSpace(line[eq+1:]))
			if key == "ignore-scripts" && val == "true" {
				return true
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(targetDir, "package.json")); err == nil {
		var doc rootPackagePnpmDoc
		if json.Unmarshal(data, &doc) == nil && doc.Pnpm.OnlyBuiltDependencies != nil {
			return true
		}
	}
	return false
}

// scanWorkspaceLifecycleHooks walks all workspace package.json, setup.py, pyproject.toml,
// Go //go:generate directives, Elixir mix.exs NIF compilers, and suspicious Makefiles.
func scanWorkspaceLifecycleHooks(targetDir string, allowlistRegexes []*regexp.Regexp) []types.SecurityFinding {
	var findings []types.SecurityFinding

	_ = filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
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
		rel, relErr := filepath.Rel(targetDir, path)
		if relErr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if isAllowlistedPath(relSlash, allowlistRegexes) {
			return nil
		}

		switch {
		case name == "package.json":
			findings = append(findings, scanPackageJSONHooks(relSlash, path)...)
		case name == "setup.py":
			findings = append(findings, scanSetupPyHooks(relSlash, path)...)
		case name == "pyproject.toml":
			findings = append(findings, scanPyprojectHooks(relSlash, path)...)
		case strings.HasSuffix(strings.ToLower(name), ".go"):
			findings = append(findings, scanGoGenerateHooks(relSlash, path)...)
		case name == "mix.exs":
			findings = append(findings, scanMixExsHooks(relSlash, path)...)
		case name == "Makefile" || name == "GNUmakefile":
			findings = append(findings, scanMakefileHooks(relSlash, path)...)
		}
		return nil
	})

	return findings
}

func scanPackageJSONHooks(relSlash, fullPath string) []types.SecurityFinding {
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil
	}
	var pkg packageJSONDoc
	if json.Unmarshal(data, &pkg) != nil || len(pkg.Scripts) == 0 {
		return nil
	}
	var findings []types.SecurityFinding
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
			Title:       fmt.Sprintf("Package lifecycle hook %q in %s", hook, relSlash),
			Description: fmt.Sprintf("Lifecycle script %q executes: %s", hook, cmd),
			FilePath:    relSlash,
			CWE:         "CWE-506",
		})
	}
	return findings
}

func scanSetupPyHooks(relSlash, fullPath string) []types.SecurityFinding {
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil
	}
	if !reSetupPyDangerous.MatchString(string(data)) {
		return nil
	}
	return []types.SecurityFinding{{
		ID:          "supplychain-malicious-lifecycle-hook",
		Category:    types.CategoryMalware,
		Tool:        "supplychain",
		Severity:    types.SeverityCritical,
		Title:       fmt.Sprintf("Suspicious command or network execution in Python %s", relSlash),
		Description: "setup.py invokes subprocess, os.system, urllib, or dynamic eval/exec during package installation.",
		FilePath:    relSlash,
		CWE:         "CWE-506",
	}}
}

func stripTOMLInlineComment(line string) string {
	inSingle := false
	inDouble := false
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escaped {
			escaped = false
			continue
		}
		if inDouble {
			if c == '\\' {
				escaped = true
			} else if c == '"' {
				inDouble = false
			}
			continue
		}
		if inSingle {
			if c == '\'' {
				inSingle = false
			}
			continue
		}
		switch c {
		case '"':
			inDouble = true
		case '\'':
			inSingle = true
		case '#':
			return strings.TrimSpace(line[:i])
		}
	}
	return strings.TrimSpace(line)
}

func scanPyprojectHooks(relSlash, fullPath string) []types.SecurityFinding {
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil
	}
	var findings []types.SecurityFinding
	inBuildSystem := false
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		trimmed := stripTOMLInlineComment(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "[") {
			inBuildSystem = lower == "[build-system]"
			if strings.HasPrefix(lower, "[tool.hatch.build.hooks.") {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-malicious-lifecycle-hook",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("Custom Hatch build hook in %s", relSlash),
					Description: fmt.Sprintf("Line %d declares a custom Hatch build hook (%s) that executes arbitrary Python during package build.", i+1, trimmed),
					FilePath:    relSlash,
					Line:        i + 1,
					CWE:         "CWE-506",
				})
			}
			continue
		}
		if inBuildSystem {
			if strings.HasPrefix(lower, "backend-path") {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-malicious-lifecycle-hook",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("Local custom PEP 517 backend-path in %s", relSlash),
					Description: fmt.Sprintf("Line %d configures a local build backend via backend-path, executing arbitrary local scripts during install.", i+1),
					FilePath:    relSlash,
					Line:        i + 1,
					CWE:         "CWE-506",
				})
			} else if strings.HasPrefix(lower, "build-backend") {
				if eq := strings.IndexByte(trimmed, '='); eq >= 0 {
					rhs := strings.Trim(strings.TrimSpace(trimmed[eq+1:]), `"'`)
					if rhs != "" && !standardPythonBackends[rhs] {
						findings = append(findings, types.SecurityFinding{
							ID:          "supplychain-malicious-lifecycle-hook",
							Category:    types.CategorySupplyChain,
							Tool:        "supplychain",
							Severity:    types.SeverityHigh,
							Title:       fmt.Sprintf("Non-standard PEP 517 build-backend %q in %s", rhs, relSlash),
							Description: fmt.Sprintf("Line %d uses custom build-backend %q outside standard Python build backends.", i+1, rhs),
							FilePath:    relSlash,
							Line:        i + 1,
							CWE:         "CWE-506",
						})
					}
				}
			}
		}
	}
	return findings
}

func scanGoGenerateHooks(relSlash, fullPath string) []types.SecurityFinding {
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil
	}
	var findings []types.SecurityFinding
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "//go:generate ") {
			continue
		}
		directive := strings.TrimSpace(strings.TrimPrefix(line, "//go:generate "))
		if reGoGenerateDangerous.MatchString(directive) {
			findings = append(findings, types.SecurityFinding{
				ID:          "supplychain-malicious-lifecycle-hook",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("Dangerous //go:generate directive in %s", relSlash),
				Description: fmt.Sprintf("Line %d invokes a shell or network tool in //go:generate: %s", i+1, directive),
				FilePath:    relSlash,
				Line:        i + 1,
				CWE:         "CWE-506",
			})
		}
	}
	return findings
}

func scanMixExsHooks(relSlash, fullPath string) []types.SecurityFinding {
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil
	}
	var findings []types.SecurityFinding
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if reElixirNIFCompilers.MatchString(line) {
			findings = append(findings, types.SecurityFinding{
				ID:          "supplychain-malicious-lifecycle-hook",
				Category:    types.CategorySupplyChain,
				Tool:        "supplychain",
				Severity:    types.SeverityHigh,
				Title:       fmt.Sprintf("Custom native NIF compiler hook in %s", relSlash),
				Description: fmt.Sprintf("Line %d declares a native build compiler hook (e.g. :elixir_make / :rustler) in mix.exs.", i+1),
				FilePath:    relSlash,
				Line:        i + 1,
				CWE:         "CWE-506",
			})
		}
	}
	return findings
}

func scanMakefileHooks(relSlash, fullPath string) []types.SecurityFinding {
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "\t") {
			continue
		}
		if rePipeToShell.MatchString(line) || reMakefileDangerous.MatchString(line) {
			return []types.SecurityFinding{{
				ID:          "supplychain-malicious-lifecycle-hook",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("Suspicious remote download or shell execution in %s", relSlash),
				Description: fmt.Sprintf("Recipe on line %d of %s invokes curl, wget, or a reverse shell.", i+1, relSlash),
				FilePath:    relSlash,
				Line:        i + 1,
				CWE:         "CWE-506",
			}}
		}
	}
	return nil
}

type packageLockExtendedDoc struct {
	Packages map[string]struct {
		Resolved         string `json:"resolved"`
		Integrity        string `json:"integrity"`
		Link             bool   `json:"link"`
		HasInstallScript bool   `json:"hasInstallScript"`
	} `json:"packages"`
}

func scanPolyglotLockfilesAndRegistries(targetDir string, allowed map[string]bool) []types.SecurityFinding {
	var findings []types.SecurityFinding
	protected := hasInstallScriptProtection(targetDir)

	// 1. package-lock.json: registry allowlist & transitive hasInstallScript
	if data, err := os.ReadFile(filepath.Join(targetDir, "package-lock.json")); err == nil {
		var lock packageLockExtendedDoc
		if json.Unmarshal(data, &lock) == nil {
			keys := make([]string, 0, len(lock.Packages))
			for k := range lock.Packages {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			var installScriptPkgs []string
			reportedHosts := map[string]bool{}
			for _, pkgKey := range keys {
				entry := lock.Packages[pkgKey]
				if pkgKey == "" || entry.Link {
					continue
				}
				if strings.TrimSpace(entry.Resolved) != "" {
					if host, ok := isAllowedRegistryURL(entry.Resolved, allowed); !ok && !reportedHosts[host] {
						reportedHosts[host] = true
						findings = append(findings, types.SecurityFinding{
							ID:          "supplychain-untrusted-registry",
							Category:    types.CategorySupplyChain,
							Tool:        "supplychain",
							Severity:    types.SeverityHigh,
							Title:       fmt.Sprintf("Untrusted registry host %q in package-lock.json (%s)", host, pkgKey),
							Description: fmt.Sprintf("Resolved URL %q points to host %q outside the allowed registries.", entry.Resolved, host),
							FilePath:    "package-lock.json",
							CWE:         "CWE-829",
						})
					}
				}
				if entry.HasInstallScript {
					installScriptPkgs = append(installScriptPkgs, pkgKey)
				}
			}
			if len(installScriptPkgs) > 0 && !protected {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-unrestricted-install-scripts",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("Transitive install scripts enabled in package-lock.json (%d package(s), e.g. %s)", len(installScriptPkgs), installScriptPkgs[0]),
					Description: "package-lock.json contains packages with hasInstallScript:true without .npmrc ignore-scripts=true or pnpm.onlyBuiltDependencies.",
					FilePath:    "package-lock.json",
					CWE:         "CWE-829",
				})
			}
		}
	}

	// 2. pnpm-lock.yaml: integrity, tarball HTTPS/registry, requiresBuild
	if data, err := os.ReadFile(filepath.Join(targetDir, "pnpm-lock.yaml")); err == nil {
		findings = append(findings, scanPnpmLock(string(data), allowed, protected)...)
	}

	// 3. yarn.lock: integrity/checksum, resolved HTTPS/registry
	if data, err := os.ReadFile(filepath.Join(targetDir, "yarn.lock")); err == nil {
		findings = append(findings, scanYarnLock(string(data), allowed)...)
	}

	// 4. uv.lock: sha256 hash & registry/URL validation
	if data, err := os.ReadFile(filepath.Join(targetDir, "uv.lock")); err == nil {
		findings = append(findings, scanUvLock(string(data), allowed)...)
	}

	// 5. poetry.lock: sha256 hash & source URL validation
	if data, err := os.ReadFile(filepath.Join(targetDir, "poetry.lock")); err == nil {
		findings = append(findings, scanPoetryLock(string(data), allowed)...)
	}

	// 6. requirements.txt: only flag unpinned/hash-less when no uv.lock or poetry.lock exists
	hasPyLock := fileExists(filepath.Join(targetDir, "uv.lock")) || fileExists(filepath.Join(targetDir, "poetry.lock"))
	if !hasPyLock {
		if data, err := os.ReadFile(filepath.Join(targetDir, "requirements.txt")); err == nil {
			findings = append(findings, scanRequirementsTxt(string(data), allowed)...)
		}
	}

	return findings
}

func scanPnpmLock(content string, allowed map[string]bool, protected bool) []types.SecurityFinding {
	var findings []types.SecurityFinding
	lines := strings.Split(content, "\n")

	inPackages := false
	pkgIndent := -1
	currentPkg := ""
	hasResolution := false
	hasIntegrity := false
	isLocalRes := false
	tarballURL := ""
	inResolutionBlock := false
	resIndent := -1

	reportedMissingIntegrity := false
	reportedHosts := map[string]bool{}
	var requiresBuildPkgs []string

	flushPkg := func() {
		if currentPkg == "" {
			return
		}
		if tarballURL != "" {
			if strings.HasPrefix(strings.ToLower(tarballURL), "http://") {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-lockfile-integrity",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("Cleartext HTTP tarball URL in pnpm-lock.yaml for %s", currentPkg),
					Description: fmt.Sprintf("Tarball URL %q does not use HTTPS.", tarballURL),
					FilePath:    "pnpm-lock.yaml",
					CWE:         "CWE-494",
				})
			}
			if host, ok := isAllowedRegistryURL(tarballURL, allowed); !ok && !reportedHosts[host] {
				reportedHosts[host] = true
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-untrusted-registry",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("Untrusted registry host %q in pnpm-lock.yaml (%s)", host, currentPkg),
					Description: fmt.Sprintf("Tarball URL %q points to host %q outside allowed registries.", tarballURL, host),
					FilePath:    "pnpm-lock.yaml",
					CWE:         "CWE-829",
				})
			}
		}
		if hasResolution && !isLocalRes && !hasIntegrity && !reportedMissingIntegrity {
			reportedMissingIntegrity = true
			findings = append(findings, types.SecurityFinding{
				ID:          "supplychain-lockfile-integrity",
				Category:    types.CategorySupplyChain,
				Tool:        "supplychain",
				Severity:    types.SeverityHigh,
				Title:       fmt.Sprintf("Missing integrity hash in pnpm-lock.yaml for %s", currentPkg),
				Description: "Package resolution in pnpm-lock.yaml lacks a cryptographic SHA integrity digest.",
				FilePath:    "pnpm-lock.yaml",
				CWE:         "CWE-353",
			})
		}
		currentPkg = ""
		hasResolution = false
		hasIntegrity = false
		isLocalRes = false
		tarballURL = ""
		inResolutionBlock = false
		resIndent = -1
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			flushPkg()
			inPackages = trimmed == "packages:"
			pkgIndent = -1
			continue
		}
		if !inPackages {
			continue
		}
		if pkgIndent == -1 {
			pkgIndent = indent
		}
		if indent == pkgIndent && strings.HasSuffix(trimmed, ":") {
			flushPkg()
			currentPkg = strings.Trim(strings.TrimSuffix(trimmed, ":"), `"'`)
			continue
		}
		if currentPkg == "" {
			continue
		}
		if inResolutionBlock && indent <= resIndent {
			inResolutionBlock = false
		}
		if strings.HasPrefix(trimmed, "resolution:") {
			hasResolution = true
			rhs := strings.TrimSpace(strings.TrimPrefix(trimmed, "resolution:"))
			if rhs == "" {
				inResolutionBlock = true
				resIndent = indent
			} else {
				if reIntegrityAlgo.MatchString(rhs) {
					hasIntegrity = true
				}
				if strings.Contains(rhs, "directory:") || strings.Contains(rhs, "type: directory") {
					isLocalRes = true
				}
				if m := reHTTPURL.FindString(rhs); m != "" {
					tarballURL = strings.TrimRight(m, `}",']`)
				}
			}
			continue
		}
		if inResolutionBlock {
			if strings.HasPrefix(trimmed, "integrity:") && reIntegrityAlgo.MatchString(trimmed) {
				hasIntegrity = true
			}
			if strings.HasPrefix(trimmed, "directory:") || strings.Contains(trimmed, "type: directory") {
				isLocalRes = true
			}
			if strings.HasPrefix(trimmed, "tarball:") {
				tarballURL = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "tarball:")), `"'`)
			}
		}
		if strings.HasPrefix(trimmed, "requiresBuild:") {
			val := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trimmed, "requiresBuild:")))
			if val == "true" {
				requiresBuildPkgs = append(requiresBuildPkgs, currentPkg)
			}
		}
	}
	flushPkg()

	if len(requiresBuildPkgs) > 0 && !protected {
		findings = append(findings, types.SecurityFinding{
			ID:          "supplychain-unrestricted-install-scripts",
			Category:    types.CategorySupplyChain,
			Tool:        "supplychain",
			Severity:    types.SeverityHigh,
			Title:       fmt.Sprintf("Transitive build scripts enabled in pnpm-lock.yaml (%d package(s), e.g. %s)", len(requiresBuildPkgs), requiresBuildPkgs[0]),
			Description: "pnpm-lock.yaml contains packages with requiresBuild:true without .npmrc ignore-scripts=true or pnpm.onlyBuiltDependencies.",
			FilePath:    "pnpm-lock.yaml",
			CWE:         "CWE-829",
		})
	}

	return findings
}

func scanYarnLock(content string, allowed map[string]bool) []types.SecurityFinding {
	var findings []types.SecurityFinding
	lines := strings.Split(content, "\n")

	currentPkg := ""
	resolvedURL := ""
	resolutionVal := ""
	hasHash := false
	reportedMissing := false
	reportedHosts := map[string]bool{}

	flush := func() {
		if currentPkg == "" {
			return
		}
		isLocal := strings.Contains(resolutionVal, "@workspace:") || strings.Contains(resolutionVal, "@portal:") || strings.Contains(resolutionVal, "@patch:")
		if resolvedURL != "" {
			if strings.HasPrefix(strings.ToLower(resolvedURL), "http://") {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-lockfile-integrity",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("Cleartext HTTP resolved URL in yarn.lock for %s", currentPkg),
					Description: fmt.Sprintf("Resolved URL %q does not use HTTPS.", resolvedURL),
					FilePath:    "yarn.lock",
					CWE:         "CWE-494",
				})
			}
			if host, ok := isAllowedRegistryURL(resolvedURL, allowed); !ok && !reportedHosts[host] {
				reportedHosts[host] = true
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-untrusted-registry",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("Untrusted registry host %q in yarn.lock (%s)", host, currentPkg),
					Description: fmt.Sprintf("Resolved URL %q points to host %q outside allowed registries.", resolvedURL, host),
					FilePath:    "yarn.lock",
					CWE:         "CWE-829",
				})
			}
		}
		if !isLocal && (resolvedURL != "" || resolutionVal != "") && !hasHash && !reportedMissing {
			reportedMissing = true
			findings = append(findings, types.SecurityFinding{
				ID:          "supplychain-lockfile-integrity",
				Category:    types.CategorySupplyChain,
				Tool:        "supplychain",
				Severity:    types.SeverityHigh,
				Title:       fmt.Sprintf("Missing integrity/checksum hash in yarn.lock for %s", currentPkg),
				Description: "Package entry in yarn.lock lacks an integrity or checksum digest.",
				FilePath:    "yarn.lock",
				CWE:         "CWE-353",
			})
		}
		currentPkg = ""
		resolvedURL = ""
		resolutionVal = ""
		hasHash = false
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			flush()
			if trimmed == "__metadata:" {
				continue
			}
			currentPkg = strings.Trim(strings.TrimSuffix(trimmed, ":"), `"'`)
			continue
		}
		if currentPkg == "" {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "resolved "):
			resolvedURL = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "resolved ")), `"'`)
		case strings.HasPrefix(trimmed, "resolution:"):
			resolutionVal = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "resolution:")), `"'`)
		case strings.HasPrefix(trimmed, "integrity ") || strings.HasPrefix(trimmed, "integrity:") || strings.HasPrefix(trimmed, "checksum:"):
			hasHash = true
		}
	}
	flush()

	return findings
}

func scanUvLock(content string, allowed map[string]bool) []types.SecurityFinding {
	var findings []types.SecurityFinding
	lines := strings.Split(content, "\n")
	reportedMissing := false
	reportedHosts := map[string]bool{}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, m := range reTOMLURLField.FindAllStringSubmatch(trimmed, -1) {
			u := m[2]
			if strings.HasPrefix(strings.ToLower(u), "http://") {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-lockfile-integrity",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       "Cleartext HTTP URL in uv.lock",
					Description: fmt.Sprintf("Line %d of uv.lock references cleartext URL %q.", i+1, u),
					FilePath:    "uv.lock",
					Line:        i + 1,
					CWE:         "CWE-494",
				})
			}
			if host, ok := isAllowedRegistryURL(u, allowed); !ok && !reportedHosts[host] {
				reportedHosts[host] = true
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-untrusted-registry",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("Untrusted registry host %q in uv.lock", host),
					Description: fmt.Sprintf("Line %d of uv.lock references host %q outside allowed registries.", i+1, host),
					FilePath:    "uv.lock",
					Line:        i + 1,
					CWE:         "CWE-829",
				})
			}
			// Inline artifact entries (sdist / wheels) must include hash = "sha256:..."
			if strings.EqualFold(m[1], "url") && strings.Contains(trimmed, "{") && !strings.Contains(trimmed, "hash") && !reportedMissing {
				reportedMissing = true
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-lockfile-integrity",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       "Missing SHA integrity hash in uv.lock artifact entry",
					Description: fmt.Sprintf("Artifact entry on line %d of uv.lock lacks a cryptographic hash.", i+1),
					FilePath:    "uv.lock",
					Line:        i + 1,
					CWE:         "CWE-353",
				})
			}
		}
	}

	return findings
}

func scanPoetryLock(content string, allowed map[string]bool) []types.SecurityFinding {
	var findings []types.SecurityFinding
	lines := strings.Split(content, "\n")
	reportedMissing := false
	reportedHosts := map[string]bool{}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, m := range reTOMLURLField.FindAllStringSubmatch(trimmed, -1) {
			u := m[2]
			if strings.HasPrefix(strings.ToLower(u), "http://") {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-lockfile-integrity",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       "Cleartext HTTP URL in poetry.lock",
					Description: fmt.Sprintf("Line %d of poetry.lock references cleartext URL %q.", i+1, u),
					FilePath:    "poetry.lock",
					Line:        i + 1,
					CWE:         "CWE-494",
				})
			}
			if host, ok := isAllowedRegistryURL(u, allowed); !ok && !reportedHosts[host] {
				reportedHosts[host] = true
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-untrusted-registry",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("Untrusted registry host %q in poetry.lock", host),
					Description: fmt.Sprintf("Line %d of poetry.lock references host %q outside allowed registries.", i+1, host),
					FilePath:    "poetry.lock",
					Line:        i + 1,
					CWE:         "CWE-829",
				})
			}
		}
		if strings.Contains(trimmed, "{file =") && !strings.Contains(trimmed, "hash =") && !reportedMissing {
			reportedMissing = true
			findings = append(findings, types.SecurityFinding{
				ID:          "supplychain-lockfile-integrity",
				Category:    types.CategorySupplyChain,
				Tool:        "supplychain",
				Severity:    types.SeverityHigh,
				Title:       "Missing SHA hash in poetry.lock file entry",
				Description: fmt.Sprintf("File entry on line %d of poetry.lock lacks a cryptographic hash.", i+1),
				FilePath:    "poetry.lock",
				Line:        i + 1,
				CWE:         "CWE-353",
			})
		}
	}

	return findings
}

func scanRequirementsTxt(content string, allowed map[string]bool) []types.SecurityFinding {
	var findings []types.SecurityFinding
	// Join backslash-continued lines while tracking starting line numbers.
	rawLines := strings.Split(content, "\n")
	type logicalLine struct {
		lineNum int
		text    string
	}
	var logical []logicalLine
	for i := 0; i < len(rawLines); i++ {
		startLine := i + 1
		var buf strings.Builder
		for {
			part := strings.TrimSpace(rawLines[i])
			if idx := strings.IndexByte(part, '#'); idx >= 0 {
				part = strings.TrimSpace(part[:idx])
			}
			if strings.HasSuffix(part, "\\") && i+1 < len(rawLines) {
				buf.WriteString(strings.TrimSuffix(part, "\\"))
				buf.WriteByte(' ')
				i++
				continue
			}
			buf.WriteString(part)
			break
		}
		text := strings.TrimSpace(buf.String())
		if text != "" {
			logical = append(logical, logicalLine{lineNum: startLine, text: text})
		}
	}

	reportedUnpinned := false
	reportedHosts := map[string]bool{}
	for _, ll := range logical {
		for _, u := range reHTTPURL.FindAllString(ll.text, -1) {
			if strings.HasPrefix(strings.ToLower(u), "http://") {
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-lockfile-integrity",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       "Cleartext HTTP URL in requirements.txt",
					Description: fmt.Sprintf("Line %d of requirements.txt uses cleartext URL %q.", ll.lineNum, u),
					FilePath:    "requirements.txt",
					Line:        ll.lineNum,
					CWE:         "CWE-494",
				})
			}
			if host, ok := isAllowedRegistryURL(u, allowed); !ok && !reportedHosts[host] {
				reportedHosts[host] = true
				findings = append(findings, types.SecurityFinding{
					ID:          "supplychain-untrusted-registry",
					Category:    types.CategorySupplyChain,
					Tool:        "supplychain",
					Severity:    types.SeverityHigh,
					Title:       fmt.Sprintf("Untrusted registry host %q in requirements.txt", host),
					Description: fmt.Sprintf("Line %d of requirements.txt references host %q outside allowed registries.", ll.lineNum, host),
					FilePath:    "requirements.txt",
					Line:        ll.lineNum,
					CWE:         "CWE-829",
				})
			}
		}
		// Skip pip option directives.
		if strings.HasPrefix(ll.text, "-") {
			continue
		}
		hasExactPin := strings.Contains(ll.text, "==")
		hasHash := strings.Contains(ll.text, "--hash=sha256:") ||
			strings.Contains(ll.text, "--hash=sha384:") ||
			strings.Contains(ll.text, "--hash=sha512:")
		if (!hasExactPin || !hasHash) && !reportedUnpinned {
			reportedUnpinned = true
			findings = append(findings, types.SecurityFinding{
				ID:          "supplychain-lockfile-integrity",
				Category:    types.CategorySupplyChain,
				Tool:        "supplychain",
				Severity:    types.SeverityHigh,
				Title:       "Unpinned or hash-less Python requirements.txt without uv.lock/poetry.lock",
				Description: fmt.Sprintf("Line %d (%q) is not pinned with == and --hash=sha256:... and no uv.lock or poetry.lock is present.", ll.lineNum, ll.text),
				FilePath:    "requirements.txt",
				Line:        ll.lineNum,
				CWE:         "CWE-353",
			})
		}
	}

	return findings
}

type directDep struct {
	Name      string
	Ecosystem string // "npm", "pypi", "go", "hex"
	FilePath  string
}

func extractDirectDependencies(targetDir string) []directDep {
	var deps []directDep
	seen := map[string]bool{}
	add := func(eco, file, name string) {
		n := strings.TrimSpace(name)
		if n == "" {
			return
		}
		key := eco + "|" + file + "|" + n
		if seen[key] {
			return
		}
		seen[key] = true
		deps = append(deps, directDep{Name: n, Ecosystem: eco, FilePath: file})
	}

	// 1. package.json
	if data, err := os.ReadFile(filepath.Join(targetDir, "package.json")); err == nil {
		var pkg packageJSONDoc
		if json.Unmarshal(data, &pkg) == nil {
			for _, m := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
				for name := range m {
					add("npm", "package.json", name)
				}
			}
		}
	}

	// 2. pyproject.toml
	if data, err := os.ReadFile(filepath.Join(targetDir, "pyproject.toml")); err == nil {
		for _, name := range extractPyprojectDepNames(string(data)) {
			add("pypi", "pyproject.toml", name)
		}
	}

	// 3. requirements.txt
	if data, err := os.ReadFile(filepath.Join(targetDir, "requirements.txt")); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
				continue
			}
			if m := rePyReqName.FindStringSubmatch(line); len(m) > 1 {
				add("pypi", "requirements.txt", m[1])
			}
		}
	}

	// 4. mix.exs
	if data, err := os.ReadFile(filepath.Join(targetDir, "mix.exs")); err == nil {
		for _, m := range reElixirDepAtom.FindAllStringSubmatch(string(data), -1) {
			if len(m) > 1 {
				add("hex", "mix.exs", m[1])
			}
		}
	}

	// 5. go.mod (direct requires only)
	if data, err := os.ReadFile(filepath.Join(targetDir, "go.mod")); err == nil {
		inBlock := false
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			raw := scanner.Text()
			if strings.Contains(raw, "// indirect") {
				continue
			}
			line := strings.TrimSpace(raw)
			if idx := strings.Index(line, "//"); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
			if line == "" {
				continue
			}
			if inBlock {
				if line == ")" {
					inBlock = false
					continue
				}
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					add("go", "go.mod", fields[0])
				}
				continue
			}
			if strings.HasPrefix(line, "require (") || line == "require(" {
				inBlock = true
				continue
			}
			if strings.HasPrefix(line, "require ") {
				fields := strings.Fields(strings.TrimPrefix(line, "require "))
				if len(fields) >= 2 {
					add("go", "go.mod", fields[0])
				}
			}
		}
	}

	sort.Slice(deps, func(i, j int) bool {
		if deps[i].FilePath != deps[j].FilePath {
			return deps[i].FilePath < deps[j].FilePath
		}
		return deps[i].Name < deps[j].Name
	})
	return deps
}

func extractPyprojectDepNames(content string) []string {
	var names []string
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
			if eq := strings.IndexByte(line, '='); eq > 0 {
				k := strings.Trim(strings.TrimSpace(line[:eq]), `"'`)
				if k != "" && !strings.EqualFold(k, "python") {
					names = append(names, k)
				}
			}
		}
		if !inDepsArray && strings.HasPrefix(line, "dependencies") {
			eq := strings.IndexByte(line, '=')
			if eq < 0 {
				continue
			}
			rhs := strings.TrimSpace(line[eq+1:])
			if strings.HasPrefix(rhs, "[") {
				for _, m := range reTOMLQuotedString.FindAllStringSubmatch(rhs, -1) {
					spec := firstNonEmpty(m[1], m[2], m[3], m[4])
					if nm := rePyReqName.FindStringSubmatch(spec); len(nm) > 1 {
						names = append(names, nm[1])
					}
				}
				if !strings.Contains(rhs, "]") {
					inDepsArray = true
				}
			}
		} else if inDepsArray {
			if strings.HasPrefix(line, "]") {
				inDepsArray = false
				continue
			}
			for _, m := range reTOMLQuotedString.FindAllStringSubmatch(line, -1) {
				spec := firstNonEmpty(m[1], m[2], m[3], m[4])
				if nm := rePyReqName.FindStringSubmatch(spec); len(nm) > 1 {
					names = append(names, nm[1])
				}
			}
		}
	}
	return names
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// damerauLevenshtein computes the optimal string alignment (restricted Damerau-Levenshtein)
// edit distance between two ASCII/UTF-8 strings (insertions, deletions, substitutions,
// and adjacent transpositions).
func damerauLevenshtein(a, b string) int {
	ra := []rune(a)
	rb := []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
		d[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			best := d[i-1][j] + 1
			if del := d[i][j-1] + 1; del < best {
				best = del
			}
			if sub := d[i-1][j-1] + cost; sub < best {
				best = sub
			}
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				if trans := d[i-2][j-2] + 1; trans < best {
					best = trans
				}
			}
			d[i][j] = best
		}
	}
	return d[la][lb]
}

type depsDevPackageResp struct {
	Versions []struct {
		PublishedAt string `json:"publishedAt"`
		IsDefault   bool   `json:"isDefault"`
	} `json:"versions"`
}

func scanTyposquattingAndAge(ctx context.Context, targetDir string, opts ScanOptions) []types.SecurityFinding {
	deps := extractDirectDependencies(targetDir)
	if len(deps) == 0 {
		return nil
	}

	var findings []types.SecurityFinding
	var enrichTargets []directDep
	for _, dep := range deps {
		candidate := strings.ToLower(dep.Name)
		if dep.Ecosystem == "go" {
			// Check the final path segment for Go modules.
			if idx := strings.LastIndexByte(candidate, '/'); idx >= 0 {
				candidate = candidate[idx+1:]
			}
		}
		ecoKnown := curatedTopPackagesByEcosystem[dep.Ecosystem]
		ecoSet := curatedTopPackagesSetByEcosystem[dep.Ecosystem]
		if len(ecoKnown) > 0 && len(candidate) >= 4 && !strings.HasPrefix(candidate, "@") && !ecoSet[candidate] {
			normCand := strings.ReplaceAll(candidate, "-", "_")
			for _, known := range ecoKnown {
				isSwap := normCand == strings.ReplaceAll(known, "-", "_") && candidate != known
				isEdit1 := len(candidate) >= 5 && len(known) >= 5 && damerauLevenshtein(candidate, known) == 1
				if isSwap || isEdit1 {
					findings = append(findings, types.SecurityFinding{
						ID:          "supplychain-typosquat-suspect",
						Category:    types.CategorySupplyChain,
						Tool:        "supplychain",
						Severity:    types.SeverityHigh,
						Title:       fmt.Sprintf("Potential typosquatting dependency %q (similar to %q) in %s", dep.Name, known, dep.FilePath),
						Description: fmt.Sprintf("Direct dependency %q (%s) is edit-distance 1 or hyphen/underscore-swapped from popular package %q.", dep.Name, dep.Ecosystem, known),
						FilePath:    dep.FilePath,
						PackageName: dep.Name,
						CWE:         "CWE-829",
					})
					break
				}
			}
		}

		if opts.OnlineEnrich && (dep.Ecosystem == "npm" || dep.Ecosystem == "pypi" || dep.Ecosystem == "go") {
			enrichTargets = append(enrichTargets, dep)
		}
	}

	if opts.OnlineEnrich && len(enrichTargets) > 0 {
		findings = append(findings, enrichDepsDevAgesBounded(ctx, enrichTargets, opts.HTTPClient)...)
	}

	return findings
}

func enrichDepsDevAgesBounded(ctx context.Context, targets []directDep, client *http.Client) []types.SecurityFinding {
	const (
		maxWorkers            = 8
		overallEnrichBudget   = 5 * time.Second
		maxConsecutiveNetErrs = 2
	)
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	enrichCtx, cancel := context.WithTimeout(ctx, overallEnrichBudget)
	defer cancel()

	results := make([]*types.SecurityFinding, len(targets))
	jobs := make(chan int, len(targets))
	for i := range targets {
		jobs <- i
	}
	close(jobs)

	workers := maxWorkers
	if len(targets) < workers {
		workers = len(targets)
	}

	var consecutiveNetErrs atomic.Int32
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if enrichCtx.Err() != nil {
					return
				}
				f, ok, netErr := checkDepsDevPackageAge(enrichCtx, targets[idx], client)
				if netErr {
					if consecutiveNetErrs.Add(1) >= maxConsecutiveNetErrs {
						cancel()
						return
					}
					continue
				}
				consecutiveNetErrs.Store(0)
				if ok {
					fCopy := f
					results[idx] = &fCopy
				}
			}
		}()
	}
	wg.Wait()

	var findings []types.SecurityFinding
	for _, r := range results {
		if r != nil {
			findings = append(findings, *r)
		}
	}
	return findings
}

func checkDepsDevPackageAge(ctx context.Context, dep directDep, client *http.Client) (types.SecurityFinding, bool, bool) {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	endpoint := fmt.Sprintf("https://api.deps.dev/v3alpha/systems/%s/packages/%s", dep.Ecosystem, url.PathEscape(dep.Name))
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return types.SecurityFinding{}, false, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return types.SecurityFinding{}, false, true
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return types.SecurityFinding{}, false, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return types.SecurityFinding{}, false, true
	}
	var parsed depsDevPackageResp
	if json.Unmarshal(body, &parsed) != nil || len(parsed.Versions) == 0 {
		return types.SecurityFinding{}, false, false
	}

	var earliest time.Time
	for _, v := range parsed.Versions {
		if v.PublishedAt == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, v.PublishedAt)
		if err != nil {
			continue
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	if earliest.IsZero() {
		return types.SecurityFinding{}, false, false
	}
	age := time.Since(earliest)
	if age >= 0 && age < 14*24*time.Hour {
		days := int(age.Hours() / 24)
		return types.SecurityFinding{
			ID:          "supplychain-newly-published-package",
			Category:    types.CategorySupplyChain,
			Tool:        "supplychain",
			Severity:    types.SeverityMedium,
			Title:       fmt.Sprintf("Newly published package %q (%d day(s) old) in %s", dep.Name, days, dep.FilePath),
			Description: fmt.Sprintf("Package %q (%s) was first published on %s (< 14 days ago), increasing supply-chain risk.", dep.Name, dep.Ecosystem, earliest.UTC().Format(time.RFC3339)),
			FilePath:    dep.FilePath,
			PackageName: dep.Name,
			CWE:         "CWE-829",
		}, true, false
	}
	return types.SecurityFinding{}, false, false
}

// scanGitModules checks .gitmodules for cleartext http://, ext:: remote helper execution,
// or relative ../ path traversal submodule URLs.
func scanGitModules(targetDir string) []types.SecurityFinding {
	data, err := os.ReadFile(filepath.Join(targetDir, ".gitmodules"))
	if err != nil {
		return nil
	}
	var findings []types.SecurityFinding
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:eq]))
		if key != "url" {
			continue
		}
		val := strings.Trim(strings.TrimSpace(trimmed[eq+1:]), `"'`)
		lowerVal := strings.ToLower(val)
		switch {
		case strings.HasPrefix(lowerVal, "ext::"):
			findings = append(findings, types.SecurityFinding{
				ID:          "supplychain-gitmodules-hijack",
				Category:    types.CategorySupplyChain,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       "Dangerous ext:: remote helper URL in .gitmodules",
				Description: fmt.Sprintf("Line %d of .gitmodules declares an ext:: URL (%q), which can execute arbitrary commands on git clone.", i+1, val),
				FilePath:    ".gitmodules",
				Line:        i + 1,
				CWE:         "CWE-829",
			})
		case strings.HasPrefix(lowerVal, "http://"):
			findings = append(findings, types.SecurityFinding{
				ID:          "supplychain-gitmodules-hijack",
				Category:    types.CategorySupplyChain,
				Tool:        "supplychain",
				Severity:    types.SeverityHigh,
				Title:       "Cleartext http:// submodule URL in .gitmodules",
				Description: fmt.Sprintf("Line %d of .gitmodules uses insecure cleartext URL %q.", i+1, val),
				FilePath:    ".gitmodules",
				Line:        i + 1,
				CWE:         "CWE-494",
			})
		case strings.HasPrefix(val, "../") || strings.Contains(val, "/../"):
			findings = append(findings, types.SecurityFinding{
				ID:          "supplychain-gitmodules-hijack",
				Category:    types.CategorySupplyChain,
				Tool:        "supplychain",
				Severity:    types.SeverityHigh,
				Title:       "Relative ../ path traversal submodule URL in .gitmodules",
				Description: fmt.Sprintf("Line %d of .gitmodules uses relative traversal URL %q.", i+1, val),
				FilePath:    ".gitmodules",
				Line:        i + 1,
				CWE:         "CWE-829",
			})
		}
	}
	return findings
}
