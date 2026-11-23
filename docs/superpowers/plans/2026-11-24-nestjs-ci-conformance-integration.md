# NestJS Backend Boilerplate CI Conformance Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate `backend_boilerplate_conformance_tests` (`conformance-audit`) into `nestjs_backend_boilerplate` so that static architecture/security checks (`sast,graph`) and dynamic black-box audits (`pentest,load,dast`) run deterministically both locally and in GitHub Actions CI.

**Architecture:** `nestjs_backend_boilerplate` declares its route and capability contract via a root `boilerplate.manifest.json` and provides a self-contained runner script (`scripts/ci/run-conformance-audit.sh`) that provisions ephemeral RSA JWT keys, applies `.env.conformance.example`, boots the compiled Fastify/NestJS app against MongoDB and Redis, and invokes the compiled `conformance-audit` Go binary. On the auditor side (`backend_boilerplate_conformance_tests`), `internal/graph` and `internal/sast` filter out non-production test/declaration files and honor repository `.gitleaks.toml` allowlists so CI scans only production surfaces without false positives.

**Tech Stack:** Go 1.23 (`conformance-audit`), TypeScript / NestJS 12 (Fastify), MongoDB 8.0, Redis 7, Grafana k6, Semgrep, Gitleaks, Trivy, CycloneDX (`cdxgen`), OSV-Scanner, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-23-polyglot-security-load-conformance-design.md`

## Global Constraints

- Pure Go module (`module github.com/pc/backend-boilerplate-conformance-tests`), zero CGO required, standard library `net/http`, `go/parser`, `html/template`, `encoding/json`, `testing`.
- Target boilerplates must not be required to install Go or security scanner dependencies inside their own `package.json`; `conformance-audit` compiles to a single static binary.
- `CONFORMANCE_HARNESS_ENABLED=true` is strictly blocked when `NODE_ENV=production` and requires `CONFORMANCE_HARNESS_TOKEN` at boot (`NODE_ENV=test`).
- Strict CI exit gate (`StrictSecurityPolicy`): zero source module dependency cycles, zero package cycles, zero Critical/High vulnerabilities, zero failed pen-test checks, and passing k6 SLA + memory drift thresholds.

## Review Focus

- Generated TypeScript declaration directories (`.tsd-emit/`), git worktrees (`.worktrees/`), coverage artifacts (`coverage/`), and co-located test files (`src/**/tests/*.spec.ts`) in `nestjs_backend_boilerplate` must be excluded from `BuildSourceGraphFromDir` so test helpers and emitted `.d.ts` files do not pollute the production module cycle graph.
- Deliberate Semgrep test fixtures (`test/security/semgrep-fixtures/*`) and `.gitleaks.toml` allowlisted paths (`.env.example`, `*.spec.ts`) in `nestjs_backend_boilerplate` must be respected by `RunSASTSuite` so test RSA keys and rule fixtures do not trigger false-positive CI failures.
- Concurrent registration TOCTOU bursts (`race-condition-toctou-burst` in `internal/pentest`) send 10 simultaneous `POST /auth/register` requests with the same email; while `argon2.hash` is in-flight, multiple requests pass `findOne({ email })` and hit MongoDB `E11000` on `newUser.save()`, which `AuthService.register` must translate into `409 Conflict` (`ConflictException`) rather than letting `AllExceptionsFilter` return `500 Internal Server Error`.
- `validateEnv` in `nestjs_backend_boilerplate` requires `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, `COOKIE_SECRET`, `ACCESS_TOKEN_TTL`, `SESSION_TTL`, `MONGO_URI`, `REDIS_HOST`, `REDIS_PORT`, `GEOIP_DATABASE_PATH`, `HCAPTCHA_SECRET`, and (when `CONFORMANCE_HARNESS_ENABLED=true`) `CONFORMANCE_HARNESS_TOKEN`; the CI bootstrap script must populate all required variables automatically without needing committed secrets.
- When `run-conformance-audit.sh` is invoked with `--stages sast,graph` (white-box only), it must not require MongoDB, Redis, or a running NestJS HTTP server.

---

### Task 1: Harden Source Graph & SAST Scanners for Real TypeScript Repositories (`backend_boilerplate_conformance_tests`)

**Files:**
- Modify: `/Users/pc/Documents/personal/backend_boilerplate_conformance_tests/internal/graph/source_graph.go:401-458`
- Modify: `/Users/pc/Documents/personal/backend_boilerplate_conformance_tests/internal/graph/source_graph_test.go`
- Modify: `/Users/pc/Documents/personal/backend_boilerplate_conformance_tests/internal/sast/sast.go:216-281`
- Modify: `/Users/pc/Documents/personal/backend_boilerplate_conformance_tests/internal/sast/sast_test.go`

**Interfaces:**
- Produces:
  - `shouldIncludeSourceFile(relPath string, lang types.BoilerplateLanguage) bool` (excludes `*.spec.ts`, `*.test.ts`, `*.test-d.ts`, `*.d.ts`, `*.spec.tsx`, `*.test.tsx`, `*.spec.js`, `*.test.js`, and root config files outside `src/` when `src/` exists or files inside `test/`/`tests/`/`__tests__/`).
  - `BuildSourceGraphFromDir(targetDir string, lang types.BoilerplateLanguage) (types.DependencyGraph, error)` (skips any directory starting with `.` except `.`, plus `coverage`, `reports`, `test`, `tests`, `__tests__`, `scripts`, `evals`, `jest`).
  - `RunSASTSuite(ctx context.Context, targetDir string, mode runner.ExecutionMode, execFn runner.CommandExecutor) ([]types.SecurityFinding, error)` (passes `--exclude node_modules --exclude dist --exclude test/security/semgrep-fixtures` to Semgrep, passes `--config <scanPath>/.gitleaks.toml` to Gitleaks when `.gitleaks.toml` exists in `targetDir`, and passes `--skip-dirs node_modules,dist,.git,test,tests` to Trivy).

- [ ] **Step 1: Write the failing unit tests in `internal/graph/source_graph_test.go` and `internal/sast/sast_test.go`**

Add `TestBuildSourceGraphFromDir_SkipsDotDirsTestsAndDeclarations` in `/Users/pc/Documents/personal/backend_boilerplate_conformance_tests/internal/graph/source_graph_test.go`:
```go
func TestBuildSourceGraphFromDir_SkipsDotDirsTestsAndDeclarations(t *testing.T) {
	tmp := t.TempDir()
	mustWrite := func(rel, content string) {
		full := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mustWrite("tsconfig.json", `{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}`)
	mustWrite("src/app.module.ts", `import { AuthService } from '@/auth/auth.service'; export class AppModule {}`)
	mustWrite("src/auth/auth.service.ts", `export class AuthService {}`)
	mustWrite("src/auth/tests/auth.service.spec.ts", `import { AppModule } from '@/app.module'; import { AuthService } from '@/auth/auth.service';`)
	mustWrite(".tsd-emit/app.module.d.ts", `import { AuthService } from './auth/auth.service';`)
	mustWrite(".worktrees/old/src/cycle.ts", `import './cycle';`)
	mustWrite("coverage/prettify.js", `function prettify() {}`)

	g, err := BuildSourceGraphFromDir(tmp, types.LangTypeScript)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(g.Nodes) != 2 {
		t.Fatalf("expected 2 production nodes, got %d: %+v", len(g.Nodes), g.Nodes)
	}
}
```

Add `TestRunSASTSuite_IncludesExclusionsAndGitleaksConfig` in `/Users/pc/Documents/personal/backend_boilerplate_conformance_tests/internal/sast/sast_test.go`:
```go
func TestRunSASTSuite_IncludesExclusionsAndGitleaksConfig(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".gitleaks.toml"), []byte("title = \"test\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var calls []runner.ResolvedCommand
	mockExec := func(ctx context.Context, cmd runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		calls = append(calls, cmd)
		return runner.ToolExecutionResult{ExitCode: 0, Stdout: "", OK: true, Mode: cmd.Mode}, nil
	}

	_, err := RunSASTSuite(context.Background(), tmp, runner.ModeLocal, mockExec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("expected 3 tool calls, got %d", len(calls))
	}
	if !slices.Contains(calls[0].Args, "test/security/semgrep-fixtures") {
		t.Fatalf("expected semgrep args to exclude test/security/semgrep-fixtures, got %v", calls[0].Args)
	}
	if !slices.Contains(calls[1].Args, "--config") {
		t.Fatalf("expected gitleaks args to include --config when .gitleaks.toml exists, got %v", calls[1].Args)
	}
	if !slices.Contains(calls[2].Args, "--skip-dirs") {
		t.Fatalf("expected trivy args to include --skip-dirs, got %v", calls[2].Args)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -v ./internal/graph ./internal/sast -run "TestBuildSourceGraphFromDir_SkipsDotDirsTestsAndDeclarations|TestRunSASTSuite_IncludesExclusionsAndGitleaksConfig"`
Expected: FAIL (`expected 2 production nodes, got 6` and `expected semgrep args to exclude test/security/semgrep-fixtures`).

- [ ] **Step 3: Update `internal/graph/source_graph.go` and `internal/sast/sast.go`**

In `internal/graph/source_graph.go`:
- Update `shouldIncludeSourceFile(relPath string, lang types.BoilerplateLanguage) bool`: for `LangTypeScript` / `LangJavaScript`, return `false` if `relPath` ends with `.d.ts`, `.spec.ts`, `.test.ts`, `.test-d.ts`, `.spec.tsx`, `.test.tsx`, `.spec.js`, `.test.js`, `.spec.mjs`, or `.test.mjs`.
- Update `BuildSourceGraphFromDir`: skip any directory where `d.Name() != "." && strings.HasPrefix(d.Name(), ".")`, and add `"coverage": true, "reports": true, "test": true, "tests": true, "__tests__": true, "evals": true, "jest": true, "scripts": true` to `skipDirs`.

In `internal/sast/sast.go`:
- In `RunSASTSuite`, pass `"--exclude", "node_modules", "--exclude", "dist", "--exclude", "test/security/semgrep-fixtures"` to Semgrep.
- Check if `filepath.Join(targetDir, ".gitleaks.toml")` exists on disk; if so, append `"--config", filepath.ToSlash(filepath.Join(scanPathFor(runner.ToolGitleaks), ".gitleaks.toml"))` to Gitleaks `Args`.
- Pass `"--skip-dirs", "node_modules,dist,.git,test,tests"` to Trivy `Args`.

- [ ] **Step 4: Run tests and recompile `bin/conformance-audit`**

Run: `go test -v ./internal/graph ./internal/sast && go build -o ./bin/conformance-audit ./cmd/conformance-audit`
Expected: PASS and updated `./bin/conformance-audit` binary compiled with exit code 0.

- [ ] **Step 5: Commit in `backend_boilerplate_conformance_tests`**

```bash
git add internal/graph/source_graph.go internal/graph/source_graph_test.go internal/sast/sast.go internal/sast/sast_test.go bin/conformance-audit
git commit -m "feat(sast,graph): filter non-prod TS artifacts and respect .gitleaks.toml"
```

---

### Task 2: Fix Concurrent Registration TOCTOU `E11000` Handling & Add `boilerplate.manifest.json` (`nestjs_backend_boilerplate`)

**Files:**
- Modify: `/Users/pc/Documents/personal/nestjs_backend_boilerplate/src/auth/auth.service.ts:36-60`
- Modify: `/Users/pc/Documents/personal/nestjs_backend_boilerplate/src/auth/tests/auth.service.spec.ts`
- Create: `/Users/pc/Documents/personal/nestjs_backend_boilerplate/boilerplate.manifest.json`

**Interfaces:**
- Consumes: `types.BoilerplateManifest` schema (`schemas/boilerplate-manifest.schema.json`).
- Produces:
  - `AuthService.register(registerDto: RegisterDto): Promise<void>` translating Mongo duplicate-key error (`code === 11000`) from `newUser.save()` into `ConflictException('Email already in use')`.
  - `/Users/pc/Documents/personal/nestjs_backend_boilerplate/boilerplate.manifest.json` declaring `health` (`GET /health/live`), `auth` (`/auth/register`, `/auth/login`, `GET /`, `/auth/refresh`), `rbac` (`GET /feature-flags`), and `websockets` (`GET /socket.io/?EIO=4&transport=websocket`).

- [ ] **Step 1: Write the failing unit test in `nestjs_backend_boilerplate/src/auth/tests/auth.service.spec.ts`**

Inspect `/Users/pc/Documents/personal/nestjs_backend_boilerplate/src/auth/tests/auth.service.spec.ts` and add a test case in the `register` describe block:
```typescript
it('translates concurrent MongoDB E11000 duplicate key error on save into ConflictException', async () => {
  userModel.findOne.mockReturnValue({
    exec: jest.fn<() => Promise<null>>().mockResolvedValue(null),
  });
  saveMock.mockRejectedValueOnce(Object.assign(new Error('E11000 duplicate key error'), { code: 11000 }));

  await expect(
    service.register({ email: 'race@example.com', password: 'Password123!' }),
  ).rejects.toThrow(ConflictException);
});
```

- [ ] **Step 2: Run the unit test in `nestjs_backend_boilerplate` to verify it fails**

Run: `cd /Users/pc/Documents/personal/nestjs_backend_boilerplate && pnpm test:unit -- src/auth/tests/auth.service.spec.ts`
Expected: FAIL (`Received promise rejected instead of ConflictException: Error: E11000 duplicate key error`).

- [ ] **Step 3: Implement E11000 catch in `src/auth/auth.service.ts` and create `boilerplate.manifest.json`**

In `/Users/pc/Documents/personal/nestjs_backend_boilerplate/src/auth/auth.service.ts`, wrap `await newUser.save()` in `register`:
```typescript
    try {
      await newUser.save();
    } catch (error: unknown) {
      if (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        (error as { code?: unknown }).code === 11000
      ) {
        throw new ConflictException('Email already in use');
      }
      throw error;
    }
```

Create `/Users/pc/Documents/personal/nestjs_backend_boilerplate/boilerplate.manifest.json`:
```json
{
  "name": "nestjs-backend-boilerplate",
  "language": "typescript",
  "capabilities": {
    "health": {
      "method": "GET",
      "path": "/health/live"
    },
    "auth": {
      "register": {
        "method": "POST",
        "path": "/auth/register",
        "emailField": "email",
        "passwordField": "password"
      },
      "login": {
        "method": "POST",
        "path": "/auth/login",
        "emailField": "email",
        "passwordField": "password",
        "tokenPath": "accessToken",
        "refreshPath": "sessionId"
      },
      "me": {
        "method": "GET",
        "path": "/"
      },
      "refresh": {
        "method": "POST",
        "path": "/auth/refresh"
      }
    },
    "rbac": {
      "adminMethod": "GET",
      "adminPath": "/feature-flags"
    },
    "websockets": {
      "enabled": true,
      "path": "/socket.io/?EIO=4&transport=websocket"
    }
  }
}
```

- [ ] **Step 4: Verify the Jest unit test passes and `conformance-audit` loads the manifest**

Run:
```bash
cd /Users/pc/Documents/personal/nestjs_backend_boilerplate && pnpm test:unit -- src/auth/tests/auth.service.spec.ts && \
cd /Users/pc/Documents/personal/backend_boilerplate_conformance_tests && ./bin/conformance-audit --target ../nestjs_backend_boilerplate --stages graph --mode local
```
Expected: Jest test PASSes, and `conformance-audit` loads `nestjs-backend-boilerplate` manifest and builds the 450-node source graph with 0 cycles.

- [ ] **Step 5: Commit in `nestjs_backend_boilerplate`**

```bash
cd /Users/pc/Documents/personal/nestjs_backend_boilerplate
git add src/auth/auth.service.ts src/auth/tests/auth.service.spec.ts boilerplate.manifest.json
git commit -m "feat(conformance): add boilerplate.manifest.json and handle TOCTOU E11000 on register"
```

---

### Task 3: Add CI Bootstrap Runner Script & NPM Scripts (`nestjs_backend_boilerplate`)

**Files:**
- Create: `/Users/pc/Documents/personal/nestjs_backend_boilerplate/scripts/ci/run-conformance-audit.sh`
- Modify: `/Users/pc/Documents/personal/nestjs_backend_boilerplate/package.json:8-38`

**Interfaces:**
- Consumes:
  - `/Users/pc/Documents/personal/nestjs_backend_boilerplate/boilerplate.manifest.json`
  - `/Users/pc/Documents/personal/nestjs_backend_boilerplate/.env.conformance.example`
  - `CONFORMANCE_AUDIT_BIN` env var (defaults to `../backend_boilerplate_conformance_tests/bin/conformance-audit`, fallback `.conformance-runner/bin/conformance-audit`).
- Produces:
  - `/Users/pc/Documents/personal/nestjs_backend_boilerplate/scripts/ci/run-conformance-audit.sh` accepting standard `conformance-audit` flags (e.g., `--stages sast,graph` or `--stages sast,graph,pentest,load --profile baseline`).
  - `pnpm quality:conformance:static` (`./scripts/ci/run-conformance-audit.sh --stages sast,graph`)
  - `pnpm quality:conformance` (`./scripts/ci/run-conformance-audit.sh --stages sast,graph,pentest,load --profile baseline`)

- [ ] **Step 1: Create `/Users/pc/Documents/personal/nestjs_backend_boilerplate/scripts/ci/run-conformance-audit.sh`**

Write `/Users/pc/Documents/personal/nestjs_backend_boilerplate/scripts/ci/run-conformance-audit.sh` and mark it executable (`chmod +x`):
- Resolves `CONFORMANCE_AUDIT_BIN` (checks `${CONFORMANCE_AUDIT_BIN:-}`, then `${ROOT_DIR}/.conformance-runner/bin/conformance-audit`, then `${ROOT_DIR}/../backend_boilerplate_conformance_tests/bin/conformance-audit`, then `command -v conformance-audit`). If missing and Go is installed with the source directory present, compiles it automatically via `go build -o <bin> ./cmd/conformance-audit`.
- Parses `--stages` from arguments (defaulting to `sast,graph,pentest,load`).
- If `--stages` only includes static stages (`sast` and/or `graph`) and no `--url` is passed: invokes `"${AUDIT_BIN}" --target "${ROOT_DIR}" --manifest "${ROOT_DIR}/boilerplate.manifest.json" "$@"` directly without starting the NestJS HTTP server.
- If `--stages` includes any dynamic stage (`pentest`, `dast`, `load`, or `all`) and `SKIP_APP_BOOT` is not `true`:
  1. Exports defaults from `.env.conformance.example` plus required test variables (`PORT="${PORT:-3000}"`, `MONGO_URI="${MONGO_URI:-mongodb://127.0.0.1:27017/nestjs-conformance}"`, `REDIS_HOST="${REDIS_HOST:-127.0.0.1}"`, `REDIS_PORT="${REDIS_PORT:-6379}"`, `COOKIE_SECRET="${COOKIE_SECRET:-conformance-cookie-secret-32-chars-min}"`, `ACCESS_TOKEN_TTL=900`, `SESSION_TTL=604800`, `CONFORMANCE_HARNESS_TOKEN="${CONFORMANCE_HARNESS_TOKEN:-conformance-harness-secret-token}"`, `GEOIP_DATABASE_PATH="${ROOT_DIR}/test/fixtures/geoip/placeholder.mmdb"`, `OTEL_ENABLED=false`, `BACKGROUND_JOBS_ENABLED=false`, `BACKGROUND_WORKER_ENABLED=false`).
  2. Generates an ephemeral 2048-bit RSA keypair using `openssl genrsa` / `openssl rsa -pubout` into a temporary directory if `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` are unset.
  3. Runs `pnpm build` if `dist/main.js` is absent, starts `node dist/main.js > /tmp/nestjs-conformance.log 2>&1 &`, registers an `EXIT` trap to terminate the process and remove temp keys, and polls `http://127.0.0.1:${PORT}/health/live` for up to 30 seconds until HTTP `200`.
  4. Executes `"${AUDIT_BIN}" --target "${ROOT_DIR}" --manifest "${ROOT_DIR}/boilerplate.manifest.json" --url "http://127.0.0.1:${PORT}" "$@"`.

- [ ] **Step 2: Add `quality:conformance:static` and `quality:conformance` scripts to `nestjs_backend_boilerplate/package.json`**

In `/Users/pc/Documents/personal/nestjs_backend_boilerplate/package.json`, add to `"scripts"`:
```json
    "quality:conformance:static": "./scripts/ci/run-conformance-audit.sh --stages sast,graph",
    "quality:conformance": "./scripts/ci/run-conformance-audit.sh --stages sast,graph,pentest,load --profile baseline"
```

- [ ] **Step 3: Test `pnpm quality:conformance:static` from `nestjs_backend_boilerplate`**

Run: `cd /Users/pc/Documents/personal/nestjs_backend_boilerplate && ./scripts/ci/run-conformance-audit.sh --stages graph`
Expected: Runs without starting the NestJS server, generates `reports/nestjs-backend-boilerplate/{scorecard.json,results.sarif,dependency-graph.mmd,dashboard.html}`, and exits with code `0`.

- [ ] **Step 4: Commit in `nestjs_backend_boilerplate`**

```bash
cd /Users/pc/Documents/personal/nestjs_backend_boilerplate
git add scripts/ci/run-conformance-audit.sh package.json
git commit -m "feat(ci): add run-conformance-audit.sh bootstrap runner and npm scripts"
```

---

### Task 4: Add GitHub Actions Conformance Workflow in `nestjs_backend_boilerplate` (`.github/workflows/conformance.yml`)

**Files:**
- Create: `/Users/pc/Documents/personal/nestjs_backend_boilerplate/.github/workflows/conformance.yml`
- Modify: `/Users/pc/Documents/personal/nestjs_backend_boilerplate/.gitignore`

**Interfaces:**
- Consumes:
  - `scripts/ci/run-conformance-audit.sh` from Task 3
  - `boilerplate.manifest.json` from Task 2
- Produces:
  - `.github/workflows/conformance.yml` running on `pull_request`, `push` (`main`, `master`), `schedule` (`0 3 * * *`), and `workflow_dispatch`.

- [ ] **Step 1: Add `.conformance-runner` to `nestjs_backend_boilerplate/.gitignore`**

Append `.conformance-runner/` to `/Users/pc/Documents/personal/nestjs_backend_boilerplate/.gitignore` so local or CI checkouts of the conformance runner repository are never tracked by git.

- [ ] **Step 2: Create `/Users/pc/Documents/personal/nestjs_backend_boilerplate/.github/workflows/conformance.yml`**

Create `/Users/pc/Documents/personal/nestjs_backend_boilerplate/.github/workflows/conformance.yml` with:
- Triggers: `pull_request`, `push` (`branches: [main, master]`), `schedule` (`- cron: '0 3 * * *'`), and `workflow_dispatch`.
- Job `conformance` on `ubuntu-latest` with `permissions: contents: read, security-events: write`.
- Services:
  - `mongo`: `image: mongo:8.0`, ports `27017:27017`, healthcheck `mongosh --eval "db.adminCommand('ping')"`.
  - `redis`: `image: redis:7`, ports `6379:6379`, healthcheck `redis-cli ping`.
- Steps:
  1. `actions/checkout@v4` (checks out `nestjs_backend_boilerplate`).
  2. `actions/checkout@v4` (checks out `${{ vars.CONFORMANCE_REPO || format('{0}/backend_boilerplate_conformance_tests', github.repository_owner) }}` into `.conformance-runner`, using `${{ secrets.CONFORMANCE_REPO_TOKEN || github.token }}`).
  3. `actions/setup-go@v5` with `go-version: '1.23'`.
  4. Build `conformance-audit`: `cd .conformance-runner && go build -o bin/conformance-audit ./cmd/conformance-audit`.
  5. `pnpm/action-setup@v4` and `actions/setup-node@v4` (`node-version-file: .nvmrc`, `cache: pnpm`).
  6. `pnpm install --frozen-lockfile && pnpm build`.
  7. Run PR/Push Conformance Gate (`if: github.event_name != 'schedule'`):
     `./scripts/ci/run-conformance-audit.sh --stages sast,graph,pentest,load --profile baseline --output reports`
  8. Run Nightly Full Soak & DAST Audit (`if: github.event_name == 'schedule'`):
     `./scripts/ci/run-conformance-audit.sh --stages all --profile soak --output reports`
  9. Upload SARIF to GitHub Security (`if: always()`):
     `github/codeql-action/upload-sarif@v3` with `sarif_file: reports/nestjs-backend-boilerplate/results.sarif`.
  10. Upload 4-part Conformance Bundle (`if: always()`):
      `actions/upload-artifact@v4` with `name: conformance-report`, `path: reports/nestjs-backend-boilerplate/`.

- [ ] **Step 3: Validate workflow YAML syntax and existing quality checks**

Run:
```bash
python3 -c 'import yaml, sys; yaml.safe_load(open("/Users/pc/Documents/personal/nestjs_backend_boilerplate/.github/workflows/conformance.yml"))' && \
cd /Users/pc/Documents/personal/nestjs_backend_boilerplate && pnpm quality:lint
```
Expected: YAML parses cleanly with exit code 0 and `pnpm quality:lint` passes.

- [ ] **Step 4: Commit in `nestjs_backend_boilerplate`**

```bash
cd /Users/pc/Documents/personal/nestjs_backend_boilerplate
git add .gitignore .github/workflows/conformance.yml
git commit -m "ci(conformance): add GitHub Actions workflow for polyglot conformance audit"
```
