package load

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/runner"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

type LoadProfile string

const (
	ProfileBaseline LoadProfile = "baseline"
	ProfileStress   LoadProfile = "stress"
	ProfileSoak     LoadProfile = "soak"
)

func normalizePath(p string) string {
	trimmed := strings.TrimSpace(p)
	if trimmed == "" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "/") {
		return "/" + trimmed
	}
	return trimmed
}

func refreshBodyKey(refreshPath string) string {
	cleaned := strings.TrimSpace(refreshPath)
	cleaned = strings.TrimPrefix(cleaned, "$.")
	cleaned = strings.TrimPrefix(cleaned, "$")
	cleaned = strings.TrimPrefix(cleaned, ".")
	parts := strings.Split(cleaned, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		if seg := strings.TrimSpace(parts[i]); seg != "" {
			return seg
		}
	}
	return "refreshToken"
}

type k6ProfileSpec struct {
	stagesJS          string
	secondaryDuration string
	thresholdsJS      string
}

func resolveK6ProfileSpec(profile LoadProfile) k6ProfileSpec {
	switch profile {
	case ProfileStress:
		return k6ProfileSpec{
			stagesJS:          `[{ duration: "15s", target: 50 }, { duration: "30s", target: 150 }, { duration: "15s", target: 0 }]`,
			secondaryDuration: "30s",
			thresholdsJS:      `"http_req_duration": ["p(95)<500", "p(99)<1000"], "http_req_failed": ["rate<0.01"]`,
		}
	case ProfileSoak:
		return k6ProfileSpec{
			stagesJS:          `[{ duration: "30s", target: 40 }, { duration: "5m", target: 40 }, { duration: "30s", target: 0 }]`,
			secondaryDuration: "5m",
			thresholdsJS:      `"http_req_duration": ["p(95)<300", "p(99)<600"], "http_req_failed": ["rate<0.005"]`,
		}
	default:
		return k6ProfileSpec{
			stagesJS:          `[{ duration: "10s", target: 20 }, { duration: "20s", target: 20 }, { duration: "10s", target: 0 }]`,
			secondaryDuration: "20s",
			thresholdsJS:      `"http_req_duration": ["p(95)<250", "p(99)<500"], "http_req_failed": ["rate<0.005"]`,
		}
	}
}

func defaultIfEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// GenerateK6Script generates a multi-scenario Grafana k6 script exercising read paths,
// optional CRUD lifecycle, auth login/refresh churn, WebSocket churn, and 4xx error-abort paths.
func GenerateK6Script(m types.BoilerplateManifest, baseURL string, profile LoadProfile) string {
	targetBase := strings.TrimRight(baseURL, "/")
	healthPath := normalizePath(m.Capabilities.Health.Path)
	spec := resolveK6ProfileSpec(profile)

	auth := m.Capabilities.Auth
	hasAuth := auth != nil && strings.TrimSpace(auth.Login.Path) != ""
	crud := m.Capabilities.CRUD
	hasCRUD := crud != nil && strings.TrimSpace(crud.CollectionPath) != "" && strings.TrimSpace(crud.ItemPath) != ""
	wsCap := m.Capabilities.WebSockets
	hasWS := wsCap != nil && wsCap.Enabled && strings.TrimSpace(wsCap.Path) != ""

	var b strings.Builder
	b.WriteString(`import http from "k6/http";` + "\n")
	if hasWS {
		b.WriteString(`import ws from "k6/ws";` + "\n")
	}
	b.WriteString(`import { check, sleep } from "k6";` + "\n\n")

	b.WriteString("export const options = {\n  scenarios: {\n")
	b.WriteString(fmt.Sprintf(`    read_steady: {
      executor: "ramping-vus",
      exec: "readSteady",
      stages: %s,
    },
`, spec.stagesJS))
	if hasCRUD {
		b.WriteString(fmt.Sprintf(`    crud_lifecycle: {
      executor: "constant-vus",
      exec: "crudLifecycle",
      vus: 2,
      duration: %q,
    },
`, spec.secondaryDuration))
	}
	if hasAuth {
		b.WriteString(fmt.Sprintf(`    auth_session_churn: {
      executor: "constant-vus",
      exec: "authSessionChurn",
      vus: 1,
      duration: %q,
    },
`, spec.secondaryDuration))
	}
	if hasWS {
		b.WriteString(fmt.Sprintf(`    ws_churn: {
      executor: "constant-vus",
      exec: "wsChurn",
      vus: 2,
      duration: %q,
    },
`, spec.secondaryDuration))
	}
	b.WriteString(fmt.Sprintf(`    error_abort_paths: {
      executor: "constant-vus",
      exec: "errorAbortPaths",
      vus: 1,
      duration: %q,
    },
  },
  thresholds: {
    %s
  },
};

const BASE_URL = __ENV.BASE_URL || %q;
`, spec.secondaryDuration, spec.thresholdsJS, targetBase))

	if hasAuth || hasCRUD {
		b.WriteString(`
function extractPath(obj, dotPath) {
  if (!obj || !dotPath) {
    return "";
  }
  const cleaned = String(dotPath).replace(/^\$\.?/, "").replace(/^\./, "");
  if (!cleaned) {
    return "";
  }
  const parts = cleaned.split(".");
  let curr = obj;
  for (let i = 0; i < parts.length; i++) {
    if (!parts[i]) {
      continue;
    }
    if (curr == null || typeof curr !== "object" || !(parts[i] in curr)) {
      return "";
    }
    curr = curr[parts[i]];
  }
  if (typeof curr === "string" || typeof curr === "number") {
    return String(curr);
  }
  return "";
}
`)
	}

	var loginPath, loginEmailField, loginPasswordField, tokenPath, refreshPath, refreshFieldKey, mePath string
	if hasAuth {
		registerPath := normalizePath(auth.Register.Path)
		loginPath = normalizePath(auth.Login.Path)
		mePath = normalizePath(auth.Me.Path)
		if auth.Refresh != nil {
			refreshPath = normalizePath(auth.Refresh.Path)
		}
		regEmailField := defaultIfEmpty(auth.Register.EmailField, "email")
		regPasswordField := defaultIfEmpty(auth.Register.PasswordField, "password")
		loginEmailField = defaultIfEmpty(auth.Login.EmailField, "email")
		loginPasswordField = defaultIfEmpty(auth.Login.PasswordField, "password")
		tokenPath = defaultIfEmpty(auth.Login.TokenPath, "accessToken")
		refreshFieldKey = refreshBodyKey(auth.Login.RefreshPath)

		extraFieldsJS := "{}"
		if len(auth.Register.ExtraFields) > 0 {
			if raw, err := json.Marshal(auth.Register.ExtraFields); err == nil {
				extraFieldsJS = string(raw)
			}
		}
		registerBlock := ""
		if registerPath != "" {
			registerBlock = fmt.Sprintf(`  const regPayload = Object.assign({}, %s, { %q: email, %q: password });
  http.post(BASE_URL + %q, JSON.stringify(regPayload), jsonHeaders);
`, extraFieldsJS, regEmailField, regPasswordField, registerPath)
		}

		b.WriteString(fmt.Sprintf(`
export function setup() {
  const email = "k6-load-" + Date.now() + "-" + Math.floor(Math.random() * 100000) + "@example.com";
  const password = "K6LoadTest!2026#Secure";
  const jsonHeaders = { headers: { "Content-Type": "application/json" } };
%s  const loginPayload = { %q: email, %q: password };
  const loginRes = http.post(BASE_URL + %q, JSON.stringify(loginPayload), jsonHeaders);
  let token = "";
  let refreshToken = "";
  try {
    const parsed = loginRes.json();
    token = extractPath(parsed, %q);
    refreshToken = extractPath(parsed, %q);
  } catch (_) {
    token = "";
  }
  if (loginRes.status < 200 || loginRes.status >= 300 || !token) {
    throw new Error("k6 setup failed: unable to acquire bearer token from " + BASE_URL + %q + " (status " + loginRes.status + ")");
  }
  return { token: token, refreshToken: refreshToken, email: email, password: password };
}
`, registerBlock, loginEmailField, loginPasswordField, loginPath, tokenPath, defaultIfEmpty(auth.Login.RefreshPath, "refreshToken"), loginPath))
	}

	meBlock := ""
	if hasAuth && mePath != "" {
		meBlock = fmt.Sprintf(`  if (data && data.token) {
    const meRes = http.get(BASE_URL + %q, {
      headers: { Authorization: "Bearer " + data.token },
    });
    check(meRes, {
      "me status is 2xx": (r) => r.status >= 200 && r.status < 300,
    });
  }
`, mePath)
	}
	b.WriteString(fmt.Sprintf(`
export function readSteady(data) {
  const healthRes = http.get(BASE_URL + %q);
  check(healthRes, {
    "health status is 2xx": (r) => r.status >= 200 && r.status < 300,
  });
%s  sleep(0.1);
}
`, healthPath, meBlock))

	if hasCRUD {
		collPath := normalizePath(crud.CollectionPath)
		itemPath := normalizePath(crud.ItemPath)
		idPath := defaultIfEmpty(crud.IDPath, "id")
		createBodyJS := `{"name":"k6-conformance-item"}`
		if len(crud.SampleCreateBody) > 0 {
			if raw, err := json.Marshal(crud.SampleCreateBody); err == nil {
				createBodyJS = string(raw)
			}
		}
		b.WriteString(fmt.Sprintf(`
export function crudLifecycle(data) {
  const headers = { "Content-Type": "application/json" };
  if (data && data.token) {
    headers["Authorization"] = "Bearer " + data.token;
  }
  const params = { headers: headers };
  const createRes = http.post(BASE_URL + %q, JSON.stringify(%s), params);
  check(createRes, {
    "crud create 2xx": (r) => r.status >= 200 && r.status < 300,
  });
  let itemId = "";
  try {
    itemId = extractPath(createRes.json(), %q);
  } catch (_) {
    itemId = "";
  }
  if (itemId) {
    const itemURL = BASE_URL + %q.replace("{id}", encodeURIComponent(itemId)).replace(":id", encodeURIComponent(itemId));
    const getRes = http.get(itemURL, params);
    check(getRes, { "crud get 2xx": (r) => r.status >= 200 && r.status < 300 });
    const patchRes = http.patch(itemURL, JSON.stringify(%s), params);
    check(patchRes, { "crud patch <500": (r) => r.status < 500 });
    const delRes = http.del(itemURL, null, params);
    check(delRes, { "crud delete 2xx": (r) => r.status >= 200 && r.status < 300 });
  }
  sleep(0.2);
}
`, collPath, createBodyJS, idPath, itemPath, createBodyJS))
	}

	if hasAuth {
		refreshBlock := ""
		if refreshPath != "" {
			refreshBlock = fmt.Sprintf(`  let sessionRefresh = "";
  try {
    sessionRefresh = extractPath(loginRes.json(), %q);
  } catch (_) {
    sessionRefresh = "";
  }
  if (sessionRefresh) {
    const refreshRes = http.post(BASE_URL + %q, JSON.stringify({ %q: sessionRefresh }), params);
    check(refreshRes, { "auth churn refresh 2xx": (r) => r.status >= 200 && r.status < 300 });
  }
`, defaultIfEmpty(auth.Login.RefreshPath, "refreshToken"), refreshPath, refreshFieldKey)
		}
		b.WriteString(fmt.Sprintf(`
export function authSessionChurn(data) {
  if (!data || !data.email) {
    sleep(0.2);
    return;
  }
  const params = { headers: { "Content-Type": "application/json" } };
  const loginRes = http.post(BASE_URL + %q, JSON.stringify({ %q: data.email, %q: data.password }), params);
  check(loginRes, { "auth churn login 2xx": (r) => r.status >= 200 && r.status < 300 });
%s  sleep(0.25);
}
`, loginPath, loginEmailField, loginPasswordField, refreshBlock))
	}

	if hasWS {
		wsPath := normalizePath(wsCap.Path)
		b.WriteString(fmt.Sprintf(`
export function wsChurn(data) {
  const wsBase = BASE_URL.replace(/^http:/, "ws:").replace(/^https:/, "wss:");
  const headers = {};
  if (data && data.token) {
    headers["Authorization"] = "Bearer " + data.token;
  }
  const res = ws.connect(wsBase + %q, { headers: headers }, function (socket) {
    socket.on("open", function () {
      socket.send(JSON.stringify({ type: "ping" }));
      socket.close();
    });
  });
  check(res, { "ws handshake ok or auth-checked": (r) => r && (r.status === 101 || r.status === 200) });
  sleep(0.25);
}
`, wsPath))
	}

	errorPath := healthPath
	if hasCRUD {
		errorPath = normalizePath(crud.CollectionPath)
	} else if hasAuth {
		errorPath = loginPath
	}
	b.WriteString(fmt.Sprintf(`
export function errorAbortPaths() {
  const errCallback = http.expectedStatuses({ min: 400, max: 499 });
  const badRes = http.post(BASE_URL + %q, "{invalid-json", {
    headers: { "Content-Type": "application/json" },
    responseCallback: errCallback,
  });
  check(badRes, { "invalid json handled cleanly (4xx)": (r) => r.status >= 400 && r.status < 500 });
  const missRes = http.get(BASE_URL + "/conformance-nonexistent-4xx-probe", {
    responseCallback: errCallback,
  });
  check(missRes, { "missing route returns 4xx": (r) => r.status >= 400 && r.status < 500 });
  sleep(0.25);
}
`, errorPath))

	return b.String()
}

type k6SummaryDoc struct {
	Metrics struct {
		HTTPReqDuration struct {
			P95        float64         `json:"p(95)"`
			P99        float64         `json:"p(99)"`
			Avg        float64         `json:"avg"`
			Thresholds map[string]bool `json:"thresholds"`
		} `json:"http_req_duration"`
		HTTPReqs struct {
			Count int64   `json:"count"`
			Rate  float64 `json:"rate"`
		} `json:"http_reqs"`
		HTTPReqFailed struct {
			Value      float64         `json:"value"`
			Rate       float64         `json:"rate"`
			Thresholds map[string]bool `json:"thresholds"`
		} `json:"http_req_failed"`
	} `json:"metrics"`
}

func ParseK6SummaryJSON(rawJSON []byte, profile LoadProfile) (types.LoadTestSummary, error) {
	var doc k6SummaryDoc
	if err := json.Unmarshal(rawJSON, &doc); err != nil {
		return types.LoadTestSummary{}, fmt.Errorf("parse k6 summary json: %w", err)
	}

	passed := true
	for _, failed := range doc.Metrics.HTTPReqDuration.Thresholds {
		if failed {
			passed = false
		}
	}
	for _, failed := range doc.Metrics.HTTPReqFailed.Thresholds {
		if failed {
			passed = false
		}
	}

	errRate := doc.Metrics.HTTPReqFailed.Value
	if errRate == 0 && doc.Metrics.HTTPReqFailed.Rate > 0 {
		errRate = doc.Metrics.HTTPReqFailed.Rate
	}

	return types.LoadTestSummary{
		Profile:       string(profile),
		Passed:        passed,
		TotalRequests: doc.Metrics.HTTPReqs.Count,
		RPS:           doc.Metrics.HTTPReqs.Rate,
		AvgMs:         doc.Metrics.HTTPReqDuration.Avg,
		P95Ms:         doc.Metrics.HTTPReqDuration.P95,
		P99Ms:         doc.Metrics.HTTPReqDuration.P99,
		ErrorRate:     errRate,
	}, nil
}

func RunK6LoadTest(ctx context.Context, m types.BoilerplateManifest, baseURL string, profile LoadProfile, mode runner.ExecutionMode, execFn runner.CommandExecutor) (*types.LoadTestSummary, error) {
	parentDir, outDir, err := runner.CreateIsolatedWorkDir("k6-conformance-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(parentDir)

	targetBase := baseURL
	effectiveMode := runner.ResolveEffectiveMode(mode, runner.ToolK6)
	if effectiveMode == runner.ModeDocker {
		targetBase = runner.RewriteURLForDocker(baseURL)
	}

	scriptContent := GenerateK6Script(m, targetBase, profile)
	scriptPath := filepath.Join(outDir, "load.js")
	summaryPath := filepath.Join(outDir, "summary.json")
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0o644); err != nil {
		return nil, err
	}

	argScript := scriptPath
	argSummary := summaryPath
	if effectiveMode == runner.ModeDocker {
		argScript = "/out/load.js"
		argSummary = "/out/summary.json"
	}

	k6Res, err := runner.RunTool(ctx, runner.ToolInvocationOptions{
		Tool:             runner.ToolK6,
		Args:             []string{"run", "--summary-trend-stats", "avg,min,med,max,p(90),p(95),p(99)", "--summary-export", argSummary, argScript},
		WorkDir:          outDir,
		Mode:             mode,
		AllowedExitCodes: []int{0, 99},
	}, execFn)
	if err != nil {
		return nil, err
	}

	rawSummary, err := os.ReadFile(summaryPath)
	if err != nil {
		return nil, err
	}
	s, err := ParseK6SummaryJSON(rawSummary, profile)
	if err != nil {
		return nil, err
	}
	if k6Res.ExitCode == 99 {
		s.Passed = false
	}
	return &s, nil
}
