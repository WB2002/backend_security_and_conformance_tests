# Polyglot Security, Dependency Cycle Graph, Pen-Test & Load-Test Conformance (Go) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the uncommitted TypeScript scaffold with a pure Go security (SAST, DAST, automated Pen-Test with race-condition probes), polyglot dependency cycle & CVE vulnerability graph (TypeScript/JS, Go, Python, Elixir), and Grafana k6 load/memory-leak conformance suite that compiles to a single static binary (`conformance-audit`) with a 4-part report bundle (HTML dashboard, Mermaid, SARIF 2.1.0, JSON scorecard) and strict CI policy gates.

**Architecture:** A pure Go module (`github.com/pc/backend-boilerplate-conformance-tests`) with zero CGO dependencies. Native Go packages handle HTTP conformance client + RFC 5737 deterministic client IP & cookie jar (`internal/httpclient`), polyglot source-code import/module extraction using `go/parser` for Go and dedicated lexical/AST resolvers for TypeScript/JS, Python, and Elixir (`internal/graph`), Tarjan SCC cycle detection with SAST/CVE "Toxic Cycle" overlay, capability-driven active Pen Testing with goroutine barrier race-condition checks and an in-process SSRF canary server (`internal/pentest`), and 4-part reporting (`internal/report`). A hybrid Docker-first tool runner (`internal/runner`) executes external scanners (`semgrep`, `gitleaks`, `trivy`, `cdxgen`, `osv-scanner`, `zap`, `nuclei`, `schemathesis`, `k6`) via pinned container images with automatic local-binary fallback.

**Tech Stack:** Go 1.23 (`net/http`, `go/parser`, `go/token`, `html/template`, `encoding/json`, `sync`, `testing`), Docker CLI / Semgrep / Gitleaks / Trivy / cdxgen / OSV-Scanner / OWASP ZAP / Nuclei / Schemathesis / Grafana k6.

**Spec:** `docs/superpowers/specs/2026-11-23-polyglot-security-load-conformance-design.md`

## Global Constraints

- Pure Go (`CGO_ENABLED=0` compatible), module path `github.com/pc/backend-boilerplate-conformance-tests`, Go 1.23+.
- Uncommitted TypeScript scaffold files (`package.json`, `pnpm-lock.yaml`, `tsconfig.json`, `vitest.config.ts`, `node_modules`, `src/`) MUST be removed in Task 1 after porting `config`, `client-ip`, `cookie-jar`, and `conformance-client` into Go (`internal/config`, `internal/httpclient`).
- `go test ./...` and `go vet ./...` MUST pass with zero errors after every task without requiring a running target server or Docker daemon.
- Supported source-graph languages: `'typescript' | 'javascript' | 'go' | 'python' | 'elixir'`.
- Default policy MUST fail (`Passed: false`, CLI exit code `1`) on ANY source module cycle (`FailOnAnySourceCycle: true`), ANY package cycle (`FailOnAnyPackageCycle: true`), ANY `critical` or `high` finding (`MaxCriticalFindings: 0`, `MaxHighFindings: 0`), ANY pen-test failure (`MaxPenTestFailures: 0`), or ANY k6/memory-leak threshold breach.

## Review Focus

- Security scanner non-zero exit codes: Scanners like `semgrep`, `gitleaks`, `trivy`, `osv-scanner`, and `zap` return exit code `1` when findings are discovered, whereas exit code `>= 2` indicates execution failure. `Runner.RunTool` must treat any exit code in `AllowedExitCodes` (default `[]int{0, 1}`) as a successful run and parse its output.
- Elixir module resolution vs file-path imports: Elixir uses `defmodule MyApp.Accounts.User` and `alias MyApp.Accounts.{Auth, Repo}` / `import` / `use` / remote calls `MyApp.Accounts.Auth.verify()`, not file paths. The Elixir graph parser must index `defmodule` names to file paths first and expand multi-alias curly braces `{A, B}`.
- Self-imports and external packages in source graphs: A file referencing other files in the same Go package, its own module, or third-party packages (`react`, `fmt`, `os`, `Phoenix.Controller`) must not create false self-loop cycles or phantom file nodes.
- Disabled or omitted optional target capabilities in `boilerplate.manifest.json`: If a boilerplate sets `websockets.enabled: false` or omits `ssrfTest`/`rbac`, the Pen-Test runner must record those checks with `Status: "skipped"` rather than failing or panicking.
- HTML & Mermaid injection / special characters in file paths or finding messages: File paths with `@`, `/`, `-`, or `<script>` / quotes in finding titles must be escaped in `dependency-graph.mmd` and `dashboard.html` so Mermaid syntax and HTML rendering never break.

---

## File Structure

- `go.mod` — Root Go module definition (`module github.com/pc/backend-boilerplate-conformance-tests`).
- `schemas/boilerplate-manifest.schema.json` — JSON Schema reference for `boilerplate.manifest.json`.
- `internal/config/config.go` — Environment config loader (`LoadConfig`) porting `src/config.ts`.
- `internal/httpclient/client.go` — Deterministic RFC 5737 `ClientIPFor`, `CookieJar`, and `ConformanceClient` porting `src/http/*.ts`.
- `internal/types/types.go` — Shared structs for manifest, findings, graphs, cycles, pen-test checks, load test summary, memory analysis, policy, and scorecard.
- `internal/manifest/manifest.go` — Manifest JSON loader, validator, and dot-path / `$.` JSON value extractor (`ExtractByPath`).
- `internal/policy/policy.go` — `StrictSecurityPolicy()` and `EvaluateSecurityPolicy(scorecard, policy)`.
- `internal/runner/runner.go` — Hybrid Docker-first / local-binary command executor with `RewriteURLForDocker` and `AllowedExitCodes`.
- `internal/sast/sast.go` — Semgrep, Gitleaks, and Trivy FS/IaC output parsers and runner orchestration.
- `internal/graph/source_graph.go` — Polyglot source-code import & module dependency graph builder for TypeScript/JS (`tsconfig` paths aware), Go (`go/parser` + `go.mod` aware), Python (relative & package aware), and Elixir (`defmodule` index + `alias`/`import`/`require`/`use`/remote call aware).
- `internal/graph/sbom_graph.go` — CycloneDX SBOM (`cdxgen`) and OSV-Scanner parser producing 3rd-party dependency edges and CVE node annotations.
- `internal/graph/cycle_analyzer.go` — Tarjan SCC + canonical elementary cycle finder and "Toxic Cycle" classifier overlaying SAST findings, CVEs, and sensitive sinks (`auth`, `crypto`, `db`, `exec`).
- `internal/dast/dast.go` — OWASP ZAP, Nuclei, and Schemathesis output parsers and runner orchestration.
- `internal/pentest/canary.go` — Ephemeral HTTP canary listener (`StartSSRFCanaryServer`) recording inbound SSRF hits.
- `internal/pentest/runner.go` — Capability-driven active Pen-Test engine (JWT tampering, BOLA/IDOR, RBAC, SQLi/NoSQLi, mass-assignment, concurrent goroutine race-condition/TOCTOU probe, SSRF canary callback, WebSocket unauthenticated probe).
- `internal/load/k6.go` — Dynamic Grafana k6 script generator (`baseline`, `stress`, `soak`) and `--summary-export` JSON parser.
- `internal/load/memory.go` — Docker container RSS memory string parser and monotonic drift / leak analyzer.
- `internal/report/report.go` — 4-part report writer (`scorecard.json`, `results.sarif`, `dependency-graph.mmd`, `dashboard.html`).
- `cmd/conformance-audit/main.go` — Unified CLI entrypoint (`--target`, `--url`, `--manifest`, `--stages`, `--profile`, `--output`, `--mode`).

---

### Task 1: Initialize Go Module, Port Config & HTTP Conformance Client, and Remove TypeScript Scaffold

**Files:**
- Create: `go.mod`
- Create: `internal/config/config.go`
- Create: `internal/httpclient/client.go`
- Create: `internal/httpclient/client_test.go`
- Modify: `.gitignore`
- Remove: `package.json`, `pnpm-lock.yaml`, `tsconfig.json`, `vitest.config.ts`, `node_modules/`, `src/`

**Interfaces:**
- Produces:
  - `internal/config`: `type ConformanceConfig struct`, `func LoadConfig(getenv func(string) string) ConformanceConfig`
  - `internal/httpclient`: `func ClientIPFor(suiteName string, index int) string`, `type CookieJar struct`, `type ConformanceClient struct`, `type RequestOptions struct`, `func NewClient(suiteName string, baseURL string, ipIndex int) *ConformanceClient`

- [ ] **Step 1: Initialize `go.mod`, clean up the old TypeScript scaffold, and write the failing test in `internal/httpclient/client_test.go`**

```go
package httpclient_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/config"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/httpclient"
)

func TestConfigAndHTTPClient(t *testing.T) {
	cfg := config.LoadConfig(func(k string) string {
		if k == "BASE_URL" {
			return "http://127.0.0.1:4000/"
		}
		return ""
	})
	if cfg.BaseURL != "http://127.0.0.1:4000" {
		t.Fatalf("expected trimmed BaseURL, got %s", cfg.BaseURL)
	}

	ip0 := httpclient.ClientIPFor("04-auth-sessions-csrf.spec.ts", 0)
	ip1 := httpclient.ClientIPFor("04-auth-sessions-csrf", 1)
	if ip0 != "198.51.100.40" || ip1 != "198.51.100.41" {
		t.Fatalf("unexpected deterministic RFC 5737 IPs: %s, %s", ip0, ip1)
	}

	var gotForwardedFor, gotCSRF, gotCookie, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotForwardedFor = r.Header.Get("X-Forwarded-For")
		gotCSRF = r.Header.Get("X-CSRF-Token")
		gotCookie = r.Header.Get("Cookie")
		gotAuth = r.Header.Get("Authorization")
		http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "csrf-xyz"})
		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "sess-1"})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := httpclient.NewClient("04-auth-sessions-csrf", srv.URL, 0)
	resp, err := client.Request(http.MethodPost, "/login", httpclient.RequestOptions{
		BearerToken: "tok-123",
		JSONBody:    map[string]string{"email": "a@b.c"},
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("first request failed: %v", err)
	}
	if gotForwardedFor != "198.51.100.40" || gotAuth != "Bearer tok-123" {
		t.Fatalf("headers mismatch: xff=%s auth=%s", gotForwardedFor, gotAuth)
	}

	_, err = client.Request(http.MethodPost, "/action", httpclient.RequestOptions{CSRF: true})
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	if gotCSRF != "csrf-xyz" || gotCookie == "" {
		t.Fatalf("expected csrf header and cookies, got csrf=%s cookie=%s", gotCSRF, gotCookie)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/...`
Expected: FAIL with missing packages `internal/config` and `internal/httpclient`.

- [ ] **Step 3: Implement `internal/config/config.go` and `internal/httpclient/client.go`**

Port `ConformanceConfig` and `LoadConfig` in `internal/config/config.go`.
Port `ClientIPFor` (FNV-1a hash + known suite slots into `198.51.100.1..250`), `CookieJar` (storing cookies, deleting on empty value/`Max-Age=0`/`1970` expires), and `ConformanceClient` in `internal/httpclient/client.go`. Update `.gitignore` for Go (`bin/`, `reports/`, `.env`, `*.test`).

- [ ] **Step 4: Run test and `go vet` to verify they pass**

Run: `go test -v ./internal/... && go vet ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add go.mod .gitignore .env.example internal/config/config.go internal/httpclient/client.go internal/httpclient/client_test.go
git commit -m "feat(core): initialize Go module and port config, cookie jar, client IP, and HTTP conformance client"
```

---

### Task 2: Core Security Types, Manifest Schema & Validator, and Policy Gate Evaluator

**Files:**
- Create: `schemas/boilerplate-manifest.schema.json`
- Create: `internal/types/types.go`
- Create: `internal/manifest/manifest.go`
- Create: `internal/policy/policy.go`
- Create: `internal/policy/policy_test.go`

**Interfaces:**
- Produces:
  - `internal/types`: `BoilerplateLanguage`, `BoilerplateManifest`, `Severity`, `FindingCategory`, `SecurityFinding`, `GraphNode`, `GraphEdge`, `DependencyGraph`, `CycleFinding`, `PenTestCheckResult`, `LoadTestSummary`, `MemorySample`, `MemoryLeakAnalysis`, `SecurityPolicy`, `PolicyEvaluationResult`, `ConformanceScorecard`
  - `internal/manifest`: `func ParseAndValidateManifest(data []byte) (types.BoilerplateManifest, error)`, `func LoadManifest(filePath string) (types.BoilerplateManifest, error)`, `func ExtractByPath(payload any, dotPath string) (any, bool)`
  - `internal/policy`: `func StrictSecurityPolicy() types.SecurityPolicy`, `func EvaluateSecurityPolicy(scorecard types.ConformanceScorecard, policy types.SecurityPolicy) types.PolicyEvaluationResult`

- [ ] **Step 1: Write the failing test in `internal/policy/policy_test.go`**

```go
package policy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/manifest"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/policy"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestManifestValidationAndExtractByPath(t *testing.T) {
	raw := []byte(`{
		"name": "elixir-phoenix-api",
		"language": "elixir",
		"openapiUrl": "/api/openapi.json",
		"capabilities": {
			"health": { "method": "GET", "path": "/health" },
			"auth": {
				"register": { "method": "POST", "path": "/api/v1/auth/register", "emailField": "email", "passwordField": "password" },
				"login": { "method": "POST", "path": "/api/v1/auth/login", "emailField": "email", "passwordField": "password", "tokenPath": "$.data.accessToken", "refreshPath": "data.refreshToken" },
				"me": { "method": "GET", "path": "/api/v1/users/me", "userIdPath": "data.id" }
			}
		}
	}`)
	m, err := manifest.ParseAndValidateManifest(raw)
	if err != nil {
		t.Fatalf("expected valid manifest, got error: %v", err)
	}
	if m.Name != "elixir-phoenix-api" || m.Language != types.LangElixir {
		t.Fatalf("unexpected manifest fields: %+v", m)
	}

	_, err = manifest.ParseAndValidateManifest([]byte(`{"name":"bad","language":"cobol","capabilities":{}}`))
	if err == nil {
		t.Fatalf("expected error for unsupported language and missing health capability")
	}

	var payload any
	_ = json.Unmarshal([]byte(`{"data":{"tokens":{"access":"jwt-999"},"id":"u-42"}}`), &payload)
	if val, ok := manifest.ExtractByPath(payload, "$.data.tokens.access"); !ok || val != "jwt-999" {
		t.Fatalf("expected jwt-999, got %v (ok=%v)", val, ok)
	}
}

func TestStrictSecurityPolicyEvaluation(t *testing.T) {
	card := types.ConformanceScorecard{
		TargetName: "go-boilerplate",
		Language:   types.LangGo,
	}
	res := policy.EvaluateSecurityPolicy(card, policy.StrictSecurityPolicy())
	if !res.Passed || len(res.Violations) != 0 {
		t.Fatalf("expected clean scorecard to pass, got %+v", res)
	}

	card.SourceGraph.Cycles = append(card.SourceGraph.Cycles, types.CycleFinding{
		ID:        "cycle-1",
		GraphType: "source",
		Nodes:     []string{"internal/auth/a.go", "internal/user/u.go", "internal/auth/a.go"},
		IsToxic:   false,
		Severity:  types.SeverityMedium,
	})
	card.Findings = append(card.Findings, types.SecurityFinding{
		ID:       "sast-1",
		Category: types.CategorySAST,
		Tool:     "semgrep",
		Severity: types.SeverityHigh,
		Title:    "Hardcoded secret",
	})
	card.PenTestResults = append(card.PenTestResults, types.PenTestCheckResult{
		ID:       "bola-1",
		Name:     "BOLA check",
		Status:   "failed",
		Severity: types.SeverityCritical,
	})

	res = policy.EvaluateSecurityPolicy(card, policy.StrictSecurityPolicy())
	if res.Passed || len(res.Violations) < 3 {
		t.Fatalf("expected policy failure with >=3 violations, got %+v", res)
	}
	if !strings.Contains(strings.ToLower(strings.Join(res.Violations, " ")), "cycle") {
		t.Fatalf("expected cycle violation message, got %v", res.Violations)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/...`
Expected: FAIL with missing packages `internal/types`, `internal/manifest`, `internal/policy`.

- [ ] **Step 3: Implement `schemas/boilerplate-manifest.schema.json`, `internal/types/types.go`, `internal/manifest/manifest.go`, and `internal/policy/policy.go`**

Implement all types in `internal/types/types.go`.
In `internal/manifest/manifest.go`, validate required fields (`name`, `language` in `typescript|javascript|go|python|elixir`, `capabilities.health.path`), apply defaults for `emailField` (`"email"`), `passwordField` (`"password"`), `tokenPath` (`"accessToken"`), and implement `ExtractByPath` supporting `$.` prefix and nested `map[string]any` traversal.
In `internal/policy/policy.go`, implement `StrictSecurityPolicy()` and `EvaluateSecurityPolicy`.

- [ ] **Step 4: Run test and `go vet` to verify they pass**

Run: `go test -v ./internal/... && go vet ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add schemas/boilerplate-manifest.schema.json internal/types/types.go internal/manifest/manifest.go internal/policy/policy.go internal/policy/policy_test.go
git commit -m "feat(policy): add security types, manifest validator, and strict security policy evaluator"
```

---

### Task 3: Hybrid Docker-First / Local-Binary Tool Runner

**Files:**
- Create: `internal/runner/runner.go`
- Create: `internal/runner/runner_test.go`

**Interfaces:**
- Produces:
  - `internal/runner`:
    - `type ToolName string` (`ToolSemgrep`, `ToolGitleaks`, `ToolTrivy`, `ToolCdxgen`, `ToolOSVScanner`, `ToolZAP`, `ToolNuclei`, `ToolSchemathesis`, `ToolK6`)
    - `type ExecutionMode string` (`ModeAuto`, `ModeDocker`, `ModeLocal`)
    - `type ToolInvocationOptions struct`
    - `type ResolvedCommand struct`
    - `type ToolExecutionResult struct`
    - `type CommandExecutor func(ctx context.Context, cmd ResolvedCommand) (ToolExecutionResult, error)`
    - `func RewriteURLForDocker(rawURL string) string`
    - `func BuildToolInvocation(opts ToolInvocationOptions) (ResolvedCommand, error)`
    - `func RunTool(ctx context.Context, opts ToolInvocationOptions, execFn CommandExecutor) (ToolExecutionResult, error)`

- [ ] **Step 1: Write the failing test in `internal/runner/runner_test.go`**

```go
package runner_test

import (
	"context"
	"slices"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/runner"
)

func TestHybridToolRunner(t *testing.T) {
	if got := runner.RewriteURLForDocker("http://127.0.0.1:3000/api"); got != "http://host.docker.internal:3000/api" {
		t.Fatalf("expected host.docker.internal rewrite, got %s", got)
	}
	if got := runner.RewriteURLForDocker("http://localhost:8080"); got != "http://host.docker.internal:8080" {
		t.Fatalf("expected localhost rewrite, got %s", got)
	}

	cmd, err := runner.BuildToolInvocation(runner.ToolInvocationOptions{
		Tool:      runner.ToolSemgrep,
		Args:      []string{"scan", "--config", "auto", "--json", "/workspace"},
		TargetDir: "/Users/pc/my-repo",
		Mode:      runner.ModeDocker,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Binary != "docker" {
		t.Fatalf("expected docker binary, got %s", cmd.Binary)
	}
	if !slices.Contains(cmd.Args, "/Users/pc/my-repo:/workspace:ro") {
		t.Fatalf("expected read-only workspace mount in %v", cmd.Args)
	}
	if !slices.Contains(cmd.Args, "semgrep/semgrep:1.102.0") {
		t.Fatalf("expected pinned semgrep image in %v", cmd.Args)
	}

	res, err := runner.RunTool(context.Background(), runner.ToolInvocationOptions{
		Tool:             runner.ToolGitleaks,
		Args:             []string{"detect"},
		Mode:             runner.ModeLocal,
		AllowedExitCodes: []int{0, 1},
	}, func(ctx context.Context, c runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		return runner.ToolExecutionResult{
			ExitCode: 1,
			Stdout:   `[{"RuleID":"aws-key"}]`,
		}, nil
	})
	if err != nil || !res.OK || res.ExitCode != 1 {
		t.Fatalf("expected exit code 1 to be treated as non-fatal OK when allowed: res=%+v err=%v", res, err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/runner/...`
Expected: FAIL with missing package `internal/runner`.

- [ ] **Step 3: Implement `internal/runner/runner.go`**

Implement tool registry mapping each `ToolName` to its binary name and pinned Docker image, `RewriteURLForDocker`, `BuildToolInvocation` (adding `--add-host=host.docker.internal:host-gateway` and volume mounts when in Docker mode), and `RunTool` (defaulting `AllowedExitCodes` to `[]int{0, 1}` and using `os/exec.CommandContext` when `execFn == nil`).

- [ ] **Step 4: Run test and `go vet` to verify they pass**

Run: `go test -v ./internal/runner/... && go vet ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go
git commit -m "feat(runner): add hybrid docker-first tool runner with local binary fallback"
```

---

### Task 4: SAST, Secrets & IaC Scanner Adapters (Semgrep, Gitleaks, Trivy)

**Files:**
- Create: `internal/sast/sast.go`
- Create: `internal/sast/sast_test.go`

**Interfaces:**
- Consumes: `internal/types`, `internal/runner`
- Produces:
  - `internal/sast`:
    - `func ParseSemgrepOutput(rawJSON []byte, targetDir string) ([]types.SecurityFinding, error)`
    - `func ParseGitleaksOutput(rawJSON []byte, targetDir string) ([]types.SecurityFinding, error)`
    - `func ParseTrivyFSOutput(rawJSON []byte, targetDir string) ([]types.SecurityFinding, error)`
    - `func RunSASTSuite(ctx context.Context, targetDir string, mode runner.ExecutionMode, execFn runner.CommandExecutor) ([]types.SecurityFinding, error)`

- [ ] **Step 1: Write the failing test in `internal/sast/sast_test.go`**

```go
package sast_test

import (
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/sast"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestSASTParsers(t *testing.T) {
	semgrepJSON := []byte(`{
		"results": [
			{
				"check_id": "go.lang.security.audit.jwt-hardcoded",
				"path": "/workspace/internal/auth/jwt.go",
				"start": { "line": 42, "col": 5 },
				"extra": {
					"severity": "ERROR",
					"message": "Hardcoded JWT secret detected",
					"metadata": { "cwe": ["CWE-798"] }
				}
			}
		]
	}`)
	findings, err := sast.ParseSemgrepOutput(semgrepJSON, "/workspace")
	if err != nil || len(findings) != 1 {
		t.Fatalf("semgrep parse failed: %v (len=%d)", err, len(findings))
	}
	if findings[0].FilePath != "internal/auth/jwt.go" || findings[0].Severity != types.SeverityHigh || findings[0].CWE != "CWE-798" {
		t.Fatalf("unexpected semgrep finding: %+v", findings[0])
	}

	gitleaksJSON := []byte(`[
		{
			"RuleID": "aws-access-token",
			"Description": "AWS Access Token",
			"File": "config/prod.exs",
			"StartLine": 19,
			"Fingerprint": "fp-123"
		}
	]`)
	gFindings, err := sast.ParseGitleaksOutput(gitleaksJSON, "")
	if err != nil || len(gFindings) != 1 || gFindings[0].Severity != types.SeverityCritical {
		t.Fatalf("gitleaks parse failed: %v %+v", err, gFindings)
	}

	trivyJSON := []byte(`{
		"Results": [
			{
				"Target": "Dockerfile",
				"Misconfigurations": [
					{
						"ID": "DS002",
						"Title": "Image user should not be root",
						"Description": "Running as root",
						"Severity": "HIGH",
						"CauseMetadata": { "StartLine": 14 }
					}
				],
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2025-1111",
						"PkgName": "lodash",
						"InstalledVersion": "4.17.15",
						"FixedVersion": "4.17.21",
						"Severity": "CRITICAL",
						"Title": "Prototype Pollution"
					}
				]
			}
		]
	}`)
	tFindings, err := sast.ParseTrivyFSOutput(trivyJSON, "")
	if err != nil || len(tFindings) != 2 {
		t.Fatalf("trivy parse failed: %v (len=%d)", err, len(tFindings))
	}
	if tFindings[0].Category != types.CategoryIaC || tFindings[1].CVE != "CVE-2025-1111" {
		t.Fatalf("unexpected trivy findings: %+v", tFindings)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sast/...`
Expected: FAIL with missing package `internal/sast`.

- [ ] **Step 3: Implement `internal/sast/sast.go`**

Implement `NormalizeRelativePath`, `ParseSemgrepOutput` (handling `cwe` as either `string` or `[]string` in Semgrep metadata), `ParseGitleaksOutput`, `ParseTrivyFSOutput`, and `RunSASTSuite`.

- [ ] **Step 4: Run test and `go vet` to verify they pass**

Run: `go test -v ./internal/sast/... && go vet ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sast/sast.go internal/sast/sast_test.go
git commit -m "feat(sast): add Semgrep, Gitleaks, and Trivy SAST/Secret/IaC parsers and runner"
```

---

### Task 5: Polyglot Source-Code Module Dependency Graph Extractor (TypeScript/JS, Go, Python, Elixir)

**Files:**
- Create: `internal/graph/source_graph.go`
- Create: `internal/graph/source_graph_test.go`

**Interfaces:**
- Consumes: `internal/types`
- Produces:
  - `internal/graph`:
    - `type SourceGraphOptions struct { Language types.BoilerplateLanguage; GoModuleName string; TSPathAliases map[string][]string }`
    - `func BuildSourceGraphFromFiles(files map[string]string, opts SourceGraphOptions) types.DependencyGraph`
    - `func BuildSourceGraphFromDir(targetDir string, lang types.BoilerplateLanguage) (types.DependencyGraph, error)`
    - `func DetectSinkCategories(filePath string, content string) []string`

- [ ] **Step 1: Write the failing test in `internal/graph/source_graph_test.go`**

```go
package graph_test

import (
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/graph"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func hasEdge(edges []types.GraphEdge, from, to string) bool {
	for _, e := range edges {
		if e.From == from && e.To == to {
			return true
		}
	}
	return false
}

func TestPolyglotSourceGraphBuilder(t *testing.T) {
	t.Run("TypeScript/JS ESM imports, NodeNext .js->.ts, and tsconfig path aliases", func(t *testing.T) {
		g := graph.BuildSourceGraphFromFiles(map[string]string{
			"src/auth/auth.service.ts": `
				import { UsersService } from '../users/users.service.js';
				import { signJwt } from '@/crypto/jwt';
			`,
			"src/users/users.service.ts": `
				import { AuthService } from '../auth/auth.service.js';
			`,
			"src/crypto/jwt.ts": `
				import crypto from 'node:crypto';
				export const signJwt = () => {};
			`,
		}, graph.SourceGraphOptions{
			Language:      types.LangTypeScript,
			TSPathAliases: map[string][]string{"@/*": {"src/*"}},
		})

		if !hasEdge(g.Edges, "src/auth/auth.service.ts", "src/users/users.service.ts") ||
			!hasEdge(g.Edges, "src/auth/auth.service.ts", "src/crypto/jwt.ts") ||
			!hasEdge(g.Edges, "src/users/users.service.ts", "src/auth/auth.service.ts") {
			t.Fatalf("missing expected TS edges in %+v", g.Edges)
		}
	})

	t.Run("Go native go/parser package imports with go.mod prefix", func(t *testing.T) {
		g := graph.BuildSourceGraphFromFiles(map[string]string{
			"internal/auth/service.go": `
				package auth
				import (
					"fmt"
					"github.com/acme/app/internal/users"
				)
			`,
			"internal/users/repo.go": `
				package users
				import "github.com/acme/app/internal/auth"
			`,
		}, graph.SourceGraphOptions{
			Language:     types.LangGo,
			GoModuleName: "github.com/acme/app",
		})

		if !hasEdge(g.Edges, "internal/auth/service.go", "internal/users/repo.go") ||
			!hasEdge(g.Edges, "internal/users/repo.go", "internal/auth/service.go") {
			t.Fatalf("missing expected Go edges in %+v", g.Edges)
		}
	})

	t.Run("Python absolute and relative from-imports", func(t *testing.T) {
		g := graph.BuildSourceGraphFromFiles(map[string]string{
			"app/auth/service.py": `
import os
from app.users import repository
from .tokens import verify_token
`,
			"app/auth/tokens.py": `
from app.users.repository import get_user
`,
			"app/users/repository.py": `
from app.auth.service import authenticate
`,
		}, graph.SourceGraphOptions{Language: types.LangPython})

		if !hasEdge(g.Edges, "app/auth/service.py", "app/users/repository.py") ||
			!hasEdge(g.Edges, "app/auth/service.py", "app/auth/tokens.py") ||
			!hasEdge(g.Edges, "app/users/repository.py", "app/auth/service.py") {
			t.Fatalf("missing expected Python edges in %+v", g.Edges)
		}
	})

	t.Run("Elixir defmodule index, multi-alias {A, B}, import/use, and remote calls", func(t *testing.T) {
		g := graph.BuildSourceGraphFromFiles(map[string]string{
			"lib/my_app/auth/guardian.ex": `
defmodule MyApp.Auth.Guardian do
  use Joken.Config
  alias MyApp.Accounts.{User, Permissions}
  def verify(token), do: MyApp.Accounts.User.find(token)
end
`,
			"lib/my_app/accounts/user.ex": `
defmodule MyApp.Accounts.User do
  import MyApp.Auth.Guardian
  def find(id), do: id
end
`,
			"lib/my_app/accounts/permissions.ex": `
defmodule MyApp.Accounts.Permissions do
  def check(), do: :ok
end
`,
		}, graph.SourceGraphOptions{Language: types.LangElixir})

		if !hasEdge(g.Edges, "lib/my_app/auth/guardian.ex", "lib/my_app/accounts/user.ex") ||
			!hasEdge(g.Edges, "lib/my_app/auth/guardian.ex", "lib/my_app/accounts/permissions.ex") ||
			!hasEdge(g.Edges, "lib/my_app/accounts/user.ex", "lib/my_app/auth/guardian.ex") {
			t.Fatalf("missing expected Elixir edges in %+v", g.Edges)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/graph/...`
Expected: FAIL with missing package `internal/graph`.

- [ ] **Step 3: Implement `internal/graph/source_graph.go`**

Implement polyglot resolvers:
- **Go**: Use Go's standard library `go/parser` + `go/token` (`parser.ImportsOnly`) to parse every `.go` file's AST imports cleanly, mapping `<GoModuleName>/<pkgDir>` to non-test `.go` files in `<pkgDir>`.
- **TypeScript/JS**: Strip comments, extract `import`/`export ... from`, `require(...)`, `import(...)`, apply `TSPathAliases`, resolve relative paths with `.js` -> `.ts`/`.tsx` and `/index.ts` fallbacks.
- **Python**: Strip `#` comments, parse `import a.b` and `from ..a.b import c`, resolve relative dots against current directory and match `<path>.py`, `<path>/<symbol>.py`, or `<path>/__init__.py`.
- **Elixir**: Pass 1 scans `defmodule <ModuleName> do` and maps `ModuleName` -> file path; Pass 2 expands `alias|import|require|use Prefix.{A, B}` and single `alias|import|require|use Mod` plus remote module references `([A-Z][A-Za-z0-9_.]*)\.[a-z_][A-Za-z0-9_?!]*\s*\(`, adding edges to internal modules found in Pass 1 (ignoring self-edges).
- **Sink Classifier**: Tag each node's `Sinks` slice with `'auth'`, `'crypto'`, `'db'`, `'exec'`, `'network'` based on file path and source patterns.

- [ ] **Step 4: Run test and `go vet` to verify they pass**

Run: `go test -v ./internal/graph/... && go vet ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/graph/source_graph.go internal/graph/source_graph_test.go
git commit -m "feat(graph): add polyglot source module dependency graph builder for TS/JS, Go, Python, and Elixir"
```

---

### Task 6: 3rd-Party SBOM Graph Parser, Tarjan SCC Cycle Detector & "Toxic Cycle" Vulnerability Overlay

**Files:**
- Create: `internal/graph/sbom_graph.go`
- Create: `internal/graph/cycle_analyzer.go`
- Create: `internal/graph/cycle_analyzer_test.go`

**Interfaces:**
- Consumes: `internal/types`, `internal/graph/source_graph.go`
- Produces:
  - `internal/graph`:
    - `func ParseCycloneDXSBOMGraph(cdxJSON []byte, osvJSON []byte) (types.DependencyGraph, []types.SecurityFinding, error)`
    - `func FindGraphCycles(g types.DependencyGraph, graphType string, findings []types.SecurityFinding) []types.CycleFinding`
    - `func AnalyzeDependencyGraphs(sourceGraph, sbomGraph types.DependencyGraph, findings []types.SecurityFinding) (types.DependencyGraph, types.DependencyGraph)`

- [ ] **Step 1: Write the failing test in `internal/graph/cycle_analyzer_test.go`**

```go
package graph_test

import (
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/graph"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestTarjanCycleDetectorAndSBOMOverlay(t *testing.T) {
	srcGraph := types.DependencyGraph{
		Nodes: []types.GraphNode{
			{ID: "src/auth.ts", Label: "src/auth.ts", Type: "module", Sinks: []string{"auth"}},
			{ID: "src/users.ts", Label: "src/users.ts", Type: "module", Sinks: []string{"db"}},
			{ID: "src/billing.ts", Label: "src/billing.ts", Type: "module"},
			{ID: "src/utils.ts", Label: "src/utils.ts", Type: "module"},
		},
		Edges: []types.GraphEdge{
			{From: "src/auth.ts", To: "src/users.ts", Kind: "import"},
			{From: "src/users.ts", To: "src/billing.ts", Kind: "import"},
			{From: "src/billing.ts", To: "src/auth.ts", Kind: "import"},
			{From: "src/billing.ts", To: "src/utils.ts", Kind: "import"},
		},
	}
	findings := []types.SecurityFinding{
		{
			ID:       "sast-sqli",
			Category: types.CategorySAST,
			Tool:     "semgrep",
			Severity: types.SeverityHigh,
			Title:    "SQL Injection in users query",
			FilePath: "src/users.ts",
			Line:     28,
		},
	}

	cycles := graph.FindGraphCycles(srcGraph, "source", findings)
	if len(cycles) != 1 {
		t.Fatalf("expected 1 cycle, got %d: %+v", len(cycles), cycles)
	}
	if !cycles[0].IsToxic || cycles[0].Severity != types.SeverityCritical {
		t.Fatalf("expected critical toxic cycle, got %+v", cycles[0])
	}
	if len(cycles[0].RelatedFindings) != 1 || cycles[0].RelatedFindings[0] != "sast-sqli" {
		t.Fatalf("expected related finding sast-sqli, got %+v", cycles[0].RelatedFindings)
	}

	cdx := []byte(`{
		"components": [
			{ "bom-ref": "pkg:npm/pkg-a@1.0.0", "name": "pkg-a", "version": "1.0.0" },
			{ "bom-ref": "pkg:npm/pkg-b@2.0.0", "name": "pkg-b", "version": "2.0.0" }
		],
		"dependencies": [
			{ "ref": "pkg:npm/pkg-a@1.0.0", "dependsOn": ["pkg:npm/pkg-b@2.0.0"] },
			{ "ref": "pkg:npm/pkg-b@2.0.0", "dependsOn": ["pkg:npm/pkg-a@1.0.0"] }
		]
	}`)
	osv := []byte(`{
	  "results": [
	    {
	      "packages": [
	        {
	          "package": { "name": "pkg-b", "version": "2.0.0", "ecosystem": "npm" },
	          "vulnerabilities": [
	            {
	              "id": "GHSA-xxxx-yyyy",
	              "summary": "Remote code execution in pkg-b",
	              "database_specific": { "severity": "CRITICAL" }
	            }
	          ]
	        }
	      ]
	    }
	  ]
	}`)

	sbomG, scaFindings, err := graph.ParseCycloneDXSBOMGraph(cdx, osv)
	if err != nil || len(scaFindings) != 1 {
		t.Fatalf("sbom parse failed: err=%v findings=%+v", err, scaFindings)
	}
	_, analyzedSBOM := graph.AnalyzeDependencyGraphs(types.DependencyGraph{}, sbomG, scaFindings)
	if len(analyzedSBOM.Cycles) != 1 || !analyzedSBOM.Cycles[0].IsToxic {
		t.Fatalf("expected toxic SBOM package cycle, got %+v", analyzedSBOM.Cycles)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/graph/...`
Expected: FAIL with undefined `ParseCycloneDXSBOMGraph` and `FindGraphCycles`.

- [ ] **Step 3: Implement `internal/graph/sbom_graph.go` and `internal/graph/cycle_analyzer.go`**

Implement `ParseCycloneDXSBOMGraph` (building package nodes/edges from CycloneDX JSON and attaching OSV vulnerabilities) and `FindGraphCycles` (Tarjan's SCC + canonical elementary cycle enumeration + Toxic Cycle scoring when any cycle node matches a SAST/SCA finding or sensitive sink).

- [ ] **Step 4: Run test and `go vet` to verify they pass**

Run: `go test -v ./internal/graph/... && go vet ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/graph/sbom_graph.go internal/graph/cycle_analyzer.go internal/graph/cycle_analyzer_test.go
git commit -m "feat(graph): add CycloneDX/OSV SBOM graph parser, Tarjan cycle detector, and Toxic Cycle classifier"
```

---

### Task 7: OpenAPI-Driven DAST Orchestrator (OWASP ZAP, Nuclei, Schemathesis)

**Files:**
- Create: `internal/dast/dast.go`
- Create: `internal/dast/dast_test.go`

**Interfaces:**
- Consumes: `internal/types`, `internal/runner`
- Produces:
  - `internal/dast`:
    - `func ParseZAPJSONOutput(rawJSON []byte) ([]types.SecurityFinding, error)`
    - `func ParseNucleiJSONLOutput(rawJSONL []byte) ([]types.SecurityFinding, error)`
    - `func ParseSchemathesisOutput(stdout string, exitCode int) []types.SecurityFinding`
    - `func RunDASTSuite(ctx context.Context, baseURL string, openapiURL string, mode runner.ExecutionMode, execFn runner.CommandExecutor) ([]types.SecurityFinding, error)`

- [ ] **Step 1: Write the failing test in `internal/dast/dast_test.go`**

```go
package dast_test

import (
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/dast"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestDASTParsers(t *testing.T) {
	zapJSON := []byte(`{
		"site": [
			{
				"@name": "http://127.0.0.1:3000",
				"alerts": [
					{
						"pluginid": "10038",
						"alert": "Content Security Policy (CSP) Header Not Set",
						"riskcode": "2",
						"desc": "CSP header missing",
						"cweid": "693",
						"instances": [{ "uri": "http://127.0.0.1:3000/api/v1/users", "method": "GET" }]
					}
				]
			}
		]
	}`)
	zFindings, err := dast.ParseZAPJSONOutput(zapJSON)
	if err != nil || len(zFindings) != 1 || zFindings[0].Severity != types.SeverityMedium || zFindings[0].CWE != "CWE-693" {
		t.Fatalf("zap parse failed: err=%v findings=%+v", err, zFindings)
	}

	nucleiJSONL := []byte(`{"template-id":"cors-misconfig","info":{"name":"Arbitrary Origin CORS Reflection","severity":"high","description":"Reflects Origin"},"matched-at":"http://127.0.0.1:3000/api/v1/auth/login"}` + "\n")
	nFindings, err := dast.ParseNucleiJSONLOutput(nucleiJSONL)
	if err != nil || len(nFindings) != 1 || nFindings[0].Severity != types.SeverityHigh {
		t.Fatalf("nuclei parse failed: err=%v findings=%+v", err, nFindings)
	}

	schemaOut := `
=== FAILURES ===
_ POST /api/v1/projects _
- Server error: 500 Internal Server Error
`
	sFindings := dast.ParseSchemathesisOutput(schemaOut, 1)
	if len(sFindings) != 1 || sFindings[0].Endpoint != "POST /api/v1/projects" {
		t.Fatalf("schemathesis parse failed: %+v", sFindings)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/dast/...`
Expected: FAIL with missing package `internal/dast`.

- [ ] **Step 3: Implement `internal/dast/dast.go`**

Implement `ParseZAPJSONOutput`, `ParseNucleiJSONLOutput`, `ParseSchemathesisOutput`, and `RunDASTSuite`.

- [ ] **Step 4: Run test and `go vet` to verify they pass**

Run: `go test -v ./internal/dast/... && go vet ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/dast/dast.go internal/dast/dast_test.go
git commit -m "feat(dast): add OWASP ZAP, Nuclei, and Schemathesis DAST parsers and orchestrator"
```

---

### Task 8: Capability-Driven Automated Pen-Test Engine (with Goroutine Race-Condition Probe) & SSRF Canary Server

**Files:**
- Create: `internal/pentest/canary.go`
- Create: `internal/pentest/runner.go`
- Create: `internal/pentest/runner_test.go`

**Interfaces:**
- Consumes: `internal/types`, `internal/manifest`, `internal/httpclient`
- Produces:
  - `internal/pentest`:
    - `type CanaryHit struct { Method string; Path string; RemoteAddr string }`
    - `type SSRFCanaryServer struct` (`URL() string`, `Port() int`, `Hits() []CanaryHit`, `ClearHits()`, `Close()`)
    - `func StartSSRFCanaryServer(port int) (*SSRFCanaryServer, error)`
    - `func ForgeUnsignedJWT(claims map[string]any) string`
    - `func TamperJWTSignature(validJWT string) string`
    - `func RunAutomatedPenTestSuite(ctx context.Context, baseURL string, m types.BoilerplateManifest, canaryPort int) ([]types.PenTestCheckResult, error)`

- [ ] **Step 1: Write the failing test in `internal/pentest/runner_test.go`**

```go
package pentest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/manifest"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/pentest"
)

func TestAutomatedPenTestEngineAndSSRFCanary(t *testing.T) {
	forged := pentest.ForgeUnsignedJWT(map[string]any{"sub": "admin", "role": "admin"})
	if !strings.HasSuffix(forged, ".") {
		t.Fatalf("expected alg:none token to end with dot: %s", forged)
	}

	sample := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	tampered := pentest.TamperJWTSignature(sample)
	if tampered == sample || len(strings.Split(tampered, ".")) != 3 {
		t.Fatalf("unexpected tampered token: %s", tampered)
	}

	canary, err := pentest.StartSSRFCanaryServer(0)
	if err != nil {
		t.Fatalf("failed to start canary: %v", err)
	}
	defer canary.Close()

	vulnApp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)

		switch {
		case r.URL.Path == "/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		case r.URL.Path == "/api/auth/register" || r.URL.Path == "/api/auth/login":
			role, _ := body["role"].(string)
			if role == "" {
				role = "user"
			}
			tok := pentest.ForgeUnsignedJWT(map[string]any{"role": role}) + "sig123"
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"accessToken": tok, "refreshToken": "ref-1", "role": role},
			})
		case r.URL.Path == "/api/users/me":
			// Vulnerable: accepts any token including alg:none and tampered signature
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"id":"u-1","role":"admin"}}`))
		case r.URL.Path == "/api/items" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"item-owner-a"}}`))
		case strings.HasPrefix(r.URL.Path, "/api/items/"):
			// Vulnerable BOLA: allows User B to read/delete User A's item
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"id":"item-owner-a","secret":"leaked"}}`))
		case r.URL.Path == "/api/webhooks/test":
			if targetURL, ok := body["targetUrl"].(string); ok && targetURL != "" {
				resp, err := http.Get(targetURL)
				if err == nil {
					_ = resp.Body.Close()
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"fetched":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer vulnApp.Close()

	m, err := manifest.ParseAndValidateManifest([]byte(`{
		"name": "vuln-test-app",
		"language": "go",
		"capabilities": {
			"health": { "method": "GET", "path": "/health" },
			"auth": {
				"register": { "method": "POST", "path": "/api/auth/register", "emailField": "email", "passwordField": "password" },
				"login": { "method": "POST", "path": "/api/auth/login", "emailField": "email", "passwordField": "password", "tokenPath": "data.accessToken", "refreshPath": "data.refreshToken" },
				"me": { "method": "GET", "path": "/api/users/me", "userIdPath": "data.id" }
			},
			"crud": {
				"collectionPath": "/api/items",
				"itemPath": "/api/items/{id}",
				"idPath": "data.id",
				"sampleCreateBody": { "name": "secret-doc" }
			},
			"ssrfTest": {
				"enabled": true,
				"method": "POST",
				"path": "/api/webhooks/test",
				"urlField": "targetUrl"
			}
		}
	}`))
	if err != nil {
		t.Fatalf("manifest error: %v", err)
	}

	results, err := pentest.RunAutomatedPenTestSuite(context.Background(), vulnApp.URL, m, canary.Port())
	if err != nil {
		t.Fatalf("pen-test suite error: %v", err)
	}

	var failedIDs, skippedIDs []string
	for _, r := range results {
		if r.Status == "failed" {
			failedIDs = append(failedIDs, r.ID)
		} else if r.Status == "skipped" {
			skippedIDs = append(skippedIDs, r.ID)
		}
	}

	for _, expectedFail := range []string{"jwt-alg-none", "jwt-signature-tamper", "bola-cross-user-access", "ssrf-canary-callback"} {
		if !slices.Contains(failedIDs, expectedFail) {
			t.Fatalf("expected %s in failedIDs, got %v", expectedFail, failedIDs)
		}
	}
	for _, expectedSkip := range []string{"rbac-privilege-escalation", "websocket-unauthenticated-access"} {
		if !slices.Contains(skippedIDs, expectedSkip) {
			t.Fatalf("expected omitted capability %s in skippedIDs, got %v", expectedSkip, skippedIDs)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/pentest/...`
Expected: FAIL with missing package `internal/pentest`.

- [ ] **Step 3: Implement `internal/pentest/canary.go` and `internal/pentest/runner.go`**

Implement `StartSSRFCanaryServer` using `net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))` and `http.Server` recording hits thread-safely via `sync.Mutex`.
Implement `RunAutomatedPenTestSuite` with checks:
1. `jwt-alg-none`
2. `jwt-signature-tamper`
3. `auth-unauthenticated-me`
4. `bola-cross-user-access`
5. `rbac-privilege-escalation` (marked `skipped` if `m.Capabilities.RBAC == nil`)
6. `injection-nosqli-sqli-login`
7. `mass-assignment-role-elevation`
8. `race-condition-toctou-burst` (fires 10 concurrent goroutines released simultaneously via a closed `startCh` barrier against register/refresh/create to verify zero `5xx` panics or race crashes)
9. `ssrf-canary-callback` (marked `skipped` if `m.Capabilities.SSRFTest == nil || !m.Capabilities.SSRFTest.Enabled`)
10. `websocket-unauthenticated-access` (marked `skipped` if `m.Capabilities.WebSockets == nil || !m.Capabilities.WebSockets.Enabled`).

- [ ] **Step 4: Run test and `go vet` to verify they pass**

Run: `go test -v ./internal/pentest/... && go vet ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pentest/canary.go internal/pentest/runner.go internal/pentest/runner_test.go
git commit -m "feat(pentest): add capability-driven automated pen-test suite, TOCTOU race burst, and SSRF canary"
```

---

### Task 9: Grafana k6 Load-Test Generator & Docker Container Memory-Leak Monitor

**Files:**
- Create: `internal/load/k6.go`
- Create: `internal/load/memory.go`
- Create: `internal/load/load_test.go`

**Interfaces:**
- Consumes: `internal/types`, `internal/runner`
- Produces:
  - `internal/load`:
    - `type LoadProfile string` (`ProfileBaseline`, `ProfileStress`, `ProfileSoak`)
    - `func GenerateK6Script(m types.BoilerplateManifest, baseURL string, profile LoadProfile) string`
    - `func ParseK6SummaryJSON(rawJSON []byte, profile LoadProfile) (types.LoadTestSummary, error)`
    - `func ParseDockerMemUsageBytes(memUsageField string) (int64, error)`
    - `func AnalyzeMemorySamples(samples []types.MemorySample, maxAllowedDriftPercent float64) types.MemoryLeakAnalysis`

- [ ] **Step 1: Write the failing test in `internal/load/load_test.go`**

```go
package load_test

import (
	"math"
	"strings"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/load"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/manifest"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestK6GeneratorAndMemoryMonitor(t *testing.T) {
	m, _ := manifest.ParseAndValidateManifest([]byte(`{
		"name": "go-fiber-api",
		"language": "go",
		"capabilities": {
			"health": { "method": "GET", "path": "/healthz" }
		}
	}`))

	script := load.GenerateK6Script(m, "http://127.0.0.1:3000", load.ProfileBaseline)
	if !strings.Contains(script, "/healthz") || !strings.Contains(script, "p(95)<250") {
		t.Fatalf("unexpected k6 script: %s", script)
	}

	summaryJSON := []byte(`{
		"metrics": {
			"http_req_duration": {
				"p(95)": 142.5,
				"p(99)": 310.2,
				"avg": 65.1,
				"thresholds": { "p(95)<250": false, "p(99)<500": false }
			},
			"http_reqs": { "count": 4200, "rate": 70.0 },
			"http_req_failed": { "value": 0.001, "thresholds": { "rate<0.005": false } }
		}
	}`)
	summary, err := load.ParseK6SummaryJSON(summaryJSON, load.ProfileBaseline)
	if err != nil || !summary.Passed || summary.P95Ms != 142.5 || summary.RPS != 70.0 {
		t.Fatalf("k6 summary parse failed: err=%v summary=%+v", err, summary)
	}

	bytes100M, err := load.ParseDockerMemUsageBytes("100MiB / 2GiB")
	if err != nil || bytes100M != 100*1024*1024 {
		t.Fatalf("expected 100MiB in bytes, got %d (err=%v)", bytes100M, err)
	}

	var samples []types.MemorySample
	for i, mb := range []int64{100, 115, 130, 148, 165} {
		samples = append(samples, types.MemorySample{
			TimestampMs: int64(i * 1000),
			RSSBytes:    mb * 1024 * 1024,
			CPUPercent:  45.0,
		})
	}
	analysis := load.AnalyzeMemorySamples(samples, 20.0)
	if !analysis.LeakDetected || math.Abs(analysis.DriftPercent-65.0) > 0.1 {
		t.Fatalf("expected leak detected with 65%% drift, got %+v", analysis)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/load/...`
Expected: FAIL with missing package `internal/load`.

- [ ] **Step 3: Implement `internal/load/k6.go` and `internal/load/memory.go`**

Implement `GenerateK6Script`, `ParseK6SummaryJSON`, `ParseDockerMemUsageBytes`, and `AnalyzeMemorySamples`.

- [ ] **Step 4: Run test and `go vet` to verify they pass**

Run: `go test -v ./internal/load/... && go vet ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/load/k6.go internal/load/memory.go internal/load/load_test.go
git commit -m "feat(load): add Grafana k6 profile generator and Docker stats memory-leak analyzer"
```

---

### Task 10: 4-Part Report Generator (HTML Dashboard, Mermaid, SARIF 2.1.0, JSON Scorecard) & `conformance-audit` CLI Binary

**Files:**
- Create: `internal/report/report.go`
- Create: `internal/report/report_test.go`
- Create: `cmd/conformance-audit/main.go`

**Interfaces:**
- Consumes: `internal/types`, `internal/policy`, `internal/manifest`, `internal/sast`, `internal/graph`, `internal/dast`, `internal/pentest`, `internal/load`
- Produces:
  - `internal/report`:
    - `type ReportBundlePaths struct { ScorecardPath string; SARIFPath string; MermaidPath string; HTMLPath string }`
    - `func GenerateMermaidDependencyGraph(card types.ConformanceScorecard) string`
    - `func GenerateSARIFReport(card types.ConformanceScorecard) ([]byte, error)`
    - `func GenerateHTMLDashboard(card types.ConformanceScorecard, policyRes types.PolicyEvaluationResult) string`
    - `func WriteReportBundle(outputDir string, card types.ConformanceScorecard, policyRes types.PolicyEvaluationResult) (ReportBundlePaths, error)`
  - `cmd/conformance-audit/main.go`: Compiles to `bin/conformance-audit`.

- [ ] **Step 1: Write the failing test in `internal/report/report_test.go`**

```go
package report_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/policy"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/report"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestReportBundleGeneration(t *testing.T) {
	card := types.ConformanceScorecard{
		TargetName: "elixir-boilerplate",
		Language:   types.LangElixir,
		Timestamp:  "2026-11-23T23:00:00Z",
		Findings: []types.SecurityFinding{
			{
				ID:          "semgrep-1",
				Category:    types.CategorySAST,
				Tool:        "semgrep",
				Severity:    types.SeverityHigh,
				Title:       `Unsafe Atom Conversion <script>alert("xss")</script>`,
				Description: "String.to_atom on user input",
				FilePath:    "lib/app/auth.ex",
				Line:        33,
				CWE:         "CWE-400",
			},
		},
		SourceGraph: types.DependencyGraph{
			Nodes: []types.GraphNode{
				{ID: "lib/app/auth.ex", Label: "lib/app/auth.ex", Type: "module", Sinks: []string{"auth"}},
				{ID: "lib/app/users.ex", Label: "lib/app/users.ex", Type: "module", Sinks: []string{"db"}},
			},
			Edges: []types.GraphEdge{
				{From: "lib/app/auth.ex", To: "lib/app/users.ex", Kind: "import"},
				{From: "lib/app/users.ex", To: "lib/app/auth.ex", Kind: "import"},
			},
			Cycles: []types.CycleFinding{
				{
					ID:              "cycle-1",
					GraphType:       "source",
					Nodes:           []string{"lib/app/auth.ex", "lib/app/users.ex", "lib/app/auth.ex"},
					IsToxic:         true,
					Severity:        types.SeverityCritical,
					Reasons:         []string{"Contains SAST high finding"},
					RelatedFindings: []string{"semgrep-1"},
				},
			},
		},
	}

	mmd := report.GenerateMermaidDependencyGraph(card)
	if !strings.Contains(mmd, "flowchart LR") || !strings.Contains(mmd, "toxicCycle") {
		t.Fatalf("unexpected mermaid output:\n%s", mmd)
	}

	sarifBytes, err := report.GenerateSARIFReport(card)
	if err != nil {
		t.Fatalf("sarif error: %v", err)
	}
	var sarifDoc map[string]any
	if err := json.Unmarshal(sarifBytes, &sarifDoc); err != nil || sarifDoc["version"] != "2.1.0" {
		t.Fatalf("invalid sarif 2.1.0 doc: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "conformance-reports-*")
	if err != nil {
		t.Fatalf("mkdtemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	polRes := policy.EvaluateSecurityPolicy(card, policy.StrictSecurityPolicy())
	paths, err := report.WriteReportBundle(tmpDir, card, polRes)
	if err != nil {
		t.Fatalf("WriteReportBundle failed: %v", err)
	}

	htmlBytes, err := os.ReadFile(paths.HTMLPath)
	if err != nil {
		t.Fatalf("failed to read html dashboard: %v", err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "elixir-boilerplate") || !strings.Contains(htmlStr, "Toxic Cycle") {
		t.Fatalf("expected target name and Toxic Cycle badge in HTML")
	}
	if strings.Contains(htmlStr, `<script>alert("xss")</script>`) || !strings.Contains(htmlStr, "&lt;script&gt;") {
		t.Fatalf("expected HTML escaping of finding title in dashboard.html")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/...`
Expected: FAIL with missing package `internal/report`.

- [ ] **Step 3: Implement `internal/report/report.go` and `cmd/conformance-audit/main.go`**

Implement `GenerateMermaidDependencyGraph`, `GenerateSARIFReport`, `GenerateHTMLDashboard` (using `html.EscapeString` / `html/template` and embedding Cytoscape.js graph viewer + cycle/finding/pen-test/k6 tables), and `WriteReportBundle`.
Implement `cmd/conformance-audit/main.go` orchestrating `--target`, `--url`, `--manifest`, `--stages=sast,graph,dast,pentest,load`, `--profile=baseline|stress|soak`, `--output=reports`, and exiting `1` if `!policyResult.Passed`.

- [ ] **Step 4: Run all tests, `go vet`, and build the static binary to verify everything passes**

Run: `go test -v ./... && go vet ./... && go build -o bin/conformance-audit ./cmd/conformance-audit`
Expected: PASS (all package tests pass, `go vet` exits 0, and `bin/conformance-audit` binary is produced).

- [ ] **Step 5: Commit**

```bash
git add internal/report/report.go internal/report/report_test.go cmd/conformance-audit/main.go
git commit -m "feat(cli): add 4-part SARIF/Mermaid/HTML/JSON report bundle and conformance-audit Go CLI binary"
```
