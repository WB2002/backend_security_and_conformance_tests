# Polyglot Backend Boilerplate Security, Dependency Cycle Graph, Pen-Test & Load-Test Conformance Harness (Go) — Design Spec

## 1. Intent & Why
Backend boilerplates across multiple languages (**TypeScript/JS, Go, Python, and Elixir**) must meet an identical security, architectural, supply-chain, and performance standard before being used for production systems. Rather than maintaining fragmented, language-specific plugins inside each boilerplate repository—or requiring Node.js/`node_modules` just to run an audit—`backend-boilerplate-conformance-tests` is built in **pure Go**, compiling to a single zero-dependency static binary (`conformance-audit`) and testable via `go test ./...`.

It accepts:
- `TARGET_REPO_PATH` (`--target`): read-only path to the boilerplate source repository for white-box analysis (SAST, Secrets, IaC, 3rd-party SBOM CVE graph, and polyglot source-code module dependency cycle graph).
- `BASE_URL` (`--url`) + `boilerplate.manifest.json` (`--manifest`): running instance of the boilerplate for black-box dynamic testing (OpenAPI-driven DAST, capability-driven automated Pen Testing including race-condition/TOCTOU bursts, and Grafana k6 Load/Soak Testing with container memory-leak detection).

## 2. Goals, Non-Goals & Anti-Goals
- **Goals:**
  - Single static Go binary (`cmd/conformance-audit`) + `go test ./...` suite that replaces the earlier uncommitted TypeScript scaffold (porting `config`, `client-ip`, `cookie-jar`, and `conformance-client` into `internal/config` and `internal/httpclient`).
  - Hybrid Docker-first external tool runner (`internal/runner`) that uses pinned Docker containers with automatic local-binary fallback.
  - Detect **both** 3rd-party package dependency cycles + transitive CVEs (via CycloneDX SBOM + OSV/Trivy) **and** internal source-code module cycles across **TypeScript/JS, Go, Python, and Elixir**, overlaying SAST findings to highlight **"Toxic Cycles"**.
  - Support boilerplates whose route paths and payload schemas differ while sharing core capabilities via a declarative `boilerplate.manifest.json` + OpenAPI discovery.
  - Execute active, multi-step automated Pen Tests (JWT tampering, refresh-token replay & concurrent race-condition/TOCTOU burst, BOLA/IDOR, RBAC escalation, SQLi/NoSQLi, mass assignment, SSRF via `MOCK_UPSTREAM_PORT`, IP spoofing rate-limit bypass, and WebSocket auth bypass).
  - Execute Grafana k6 load testing across 3 profiles (`baseline`, `stress`, `soak`) with concurrent Docker container memory-leak monitoring.
  - Emit a 4-part output bundle in `reports/<target>/`: `dashboard.html` (interactive Cytoscape graph + k6 charts), `dependency-graph.mmd` (Mermaid), `results.sarif` (SARIF 2.1.0), and `scorecard.json`, enforcing a strict CI exit gate (`policy.json`).
- **Non-Goals:**
  - Requiring target boilerplates to install language-specific linters, security agents, or Node.js in their own environments.
- **Anti-Goals:**
  - Hardcoding a single boilerplate's URL paths into DAST, Pen-Test, or Load-Test runners.
  - Passing CI when an internal module dependency cycle, Critical/High vulnerability, pen-test exploit, or k6 SLA breach is detected under default policy.

## 3. Constraints
- **Go Toolchain & Standard Library First:** Pure Go module (`module github.com/pc/backend-boilerplate-conformance-tests`), zero CGO required, standard library `net/http`, `go/parser`, `html/template`, `encoding/json`, `testing`.
- **Target Languages Supported Out-of-the-Box:** TypeScript/JavaScript (`ts`, `tsx`, `js`, `mjs`, `cjs`), Go (`go`), Python (`py`), Elixir (`ex`, `exs`), plus universal `Dockerfile` / IaC / lockfiles (`pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`, `go.sum`, `uv.lock`, `poetry.lock`, `requirements.txt`, `mix.lock`).
- **External Scanner Execution:** Hybrid Docker-first runner with local binary fallback. Pinned container images:
  - Semgrep: `semgrep/semgrep:1.102.0`
  - Gitleaks: `zricethezav/gitleaks:v8.21.2`
  - Trivy: `aquasec/trivy:0.58.1`
  - cdxgen: `ghcr.io/cyclonedx/cdxgen:v11.1.0`
  - OSV-Scanner: `ghcr.io/google/osv-scanner:v1.9.1`
  - OWASP ZAP: `ghcr.io/zaproxy/zaproxy:stable`
  - Nuclei: `projectdiscovery/nuclei:v3.3.7`
  - Schemathesis: `schemathesis/schemathesis:stable`
  - Grafana k6: `grafana/k6:0.55.0`

## 4. Detailed Architecture (Go Package Layout)

- `cmd/conformance-audit/main.go`: CLI entrypoint (`--target`, `--url`, `--manifest`, `--stages`, `--profile`, `--output`, `--mode=auto|docker|local`).
- `internal/config`: Ports `ConformanceConfig` (`.env` / environment loader for `BASE_URL`, `SOCKET_PATH`, `MONGO_URI`, `REDIS_URL`, `POSTGRES_URL`, `MOCK_UPSTREAM_PORT`, `ADMIN_EMAIL`, `COUNTRY_US_IP`, `COUNTRY_GB_IP`, `RUN_DESTRUCTIVE`, `SHUTDOWN_COMMAND`).
- `internal/httpclient`: Ports deterministic RFC 5737 `ClientIPFor(suiteName, index)`, `CookieJar` (handling `Set-Cookie`, `Max-Age=0`, `1970` expiry, `csrf_token` extraction), and `ConformanceClient` (`X-Forwarded-For`, `Authorization: Bearer`, `X-CSRF-Token`, JSON request/response helpers).
- `internal/types`: Core structs (`BoilerplateManifest`, `SecurityFinding`, `GraphNode`, `GraphEdge`, `DependencyGraph`, `CycleFinding`, `PenTestCheckResult`, `LoadTestSummary`, `MemorySample`, `MemoryLeakAnalysis`, `SecurityPolicy`, `PolicyEvaluationResult`, `ConformanceScorecard`).
- `internal/manifest`: JSON validator for `boilerplate.manifest.json` and dot-path / `$.` JSON value extractor (`ExtractByPath`).
- `internal/policy`: `StrictSecurityPolicy()` and `EvaluateSecurityPolicy(scorecard, policy)`.
- `internal/runner`: Hybrid Docker-first / local-binary command executor with `RewriteURLForDocker` (`127.0.0.1`/`localhost` -> `host.docker.internal`) and non-fatal scanner exit code handling (`AllowedExitCodes: []int{0, 1}`).
- `internal/sast`: Semgrep, Gitleaks, and Trivy FS/IaC JSON parsers and runner.
- `internal/graph`:
  - `source_graph.go`: Polyglot source-code import/module extractor for TypeScript/JS (`tsconfig.json` `paths` aware), Go (using native `go/parser` + `go.mod` module prefix), Python (absolute & relative `.` imports), and Elixir (2-pass `defmodule` index + `alias`/`import`/`require`/`use` with `{A, B}` multi-alias expansion + remote `Mod.fn()` call resolution).
  - `sbom_graph.go`: CycloneDX SBOM (`cdxgen`) + OSV-Scanner JSON parser building the 3rd-party package dependency graph and CVE annotations.
  - `cycle_analyzer.go`: Tarjan's Strongly Connected Components (SCC) & canonical elementary cycle extractor + "Toxic Cycle" overlay with SAST findings, CVEs, and sensitive sinks (`auth`, `crypto`, `db`, `exec`).
- `internal/dast`: OWASP ZAP, Nuclei, and Schemathesis output parsers and runner.
- `internal/pentest`:
  - `canary.go`: In-process SSRF Canary HTTP server on `MOCK_UPSTREAM_PORT` recording unauthorized outbound callbacks.
  - `runner.go`: Capability-driven automated Pen-Test engine executing JWT `alg:none` forgery, signature tampering, unauthenticated access, BOLA/IDOR cross-user access, RBAC privilege escalation, SQLi/NoSQLi login bypass, mass-assignment role elevation, concurrent goroutine race-condition/TOCTOU probe, SSRF canary callback test, and WebSocket unauthenticated handshake check.
- `internal/load`:
  - `k6.go`: Dynamic Grafana k6 script generator (`baseline`, `stress`, `soak`) and `--summary-export` JSON parser.
  - `memory.go`: Docker stats memory string parser (`MiB`/`GiB`) and monotonic memory-leak drift analyzer.
- `internal/report`: 4-part report generator writing `scorecard.json`, `results.sarif` (SARIF 2.1.0), `dependency-graph.mmd` (Mermaid), and `dashboard.html` (HTML-escaped self-contained interactive Cytoscape graph + k6/pen-test dashboard).
