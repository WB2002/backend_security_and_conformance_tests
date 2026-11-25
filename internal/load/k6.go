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

func GenerateK6Script(m types.BoilerplateManifest, baseURL string, profile LoadProfile) string {
	targetBase := strings.TrimRight(baseURL, "/")
	healthPath := normalizePath(m.Capabilities.Health.Path)

	var stagesJS, thresholdsJS string
	switch profile {
	case ProfileStress:
		stagesJS = `[{ duration: "15s", target: 50 }, { duration: "30s", target: 150 }, { duration: "15s", target: 0 }]`
		thresholdsJS = `"http_req_duration": ["p(95)<500", "p(99)<1000"], "http_req_failed": ["rate<0.01"]`
	case ProfileSoak:
		stagesJS = `[{ duration: "30s", target: 40 }, { duration: "5m", target: 40 }, { duration: "30s", target: 0 }]`
		thresholdsJS = `"http_req_duration": ["p(95)<300", "p(99)<600"], "http_req_failed": ["rate<0.005"]`
	default:
		stagesJS = `[{ duration: "10s", target: 20 }, { duration: "20s", target: 20 }, { duration: "10s", target: 0 }]`
		thresholdsJS = `"http_req_duration": ["p(95)<250", "p(99)<500"], "http_req_failed": ["rate<0.005"]`
	}

	auth := m.Capabilities.Auth
	if auth == nil || strings.TrimSpace(auth.Login.Path) == "" || strings.TrimSpace(auth.Me.Path) == "" {
		return fmt.Sprintf(`import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  stages: %s,
  thresholds: {
    %s
  }
};

const BASE_URL = __ENV.BASE_URL || %q;

export default function () {
  const res = http.get(BASE_URL + %q);
  check(res, {
    "status is 2xx": (r) => r.status >= 200 && r.status < 300,
  });
  sleep(0.1);
}
`, stagesJS, thresholdsJS, targetBase, healthPath)
	}

	registerPath := normalizePath(auth.Register.Path)
	loginPath := normalizePath(auth.Login.Path)
	mePath := normalizePath(auth.Me.Path)

	regEmailField := auth.Register.EmailField
	if regEmailField == "" {
		regEmailField = "email"
	}
	regPasswordField := auth.Register.PasswordField
	if regPasswordField == "" {
		regPasswordField = "password"
	}
	loginEmailField := auth.Login.EmailField
	if loginEmailField == "" {
		loginEmailField = "email"
	}
	loginPasswordField := auth.Login.PasswordField
	if loginPasswordField == "" {
		loginPasswordField = "password"
	}
	tokenPath := auth.Login.TokenPath
	if tokenPath == "" {
		tokenPath = "accessToken"
	}

	extraFieldsJS := "{}"
	if len(auth.Register.ExtraFields) > 0 {
		if b, err := json.Marshal(auth.Register.ExtraFields); err == nil {
			extraFieldsJS = string(b)
		}
	}

	registerBlock := ""
	if registerPath != "" {
		registerBlock = fmt.Sprintf(`  const regPayload = Object.assign({}, %s, { %q: email, %q: password });
  http.post(BASE_URL + %q, JSON.stringify(regPayload), jsonHeaders);
`, extraFieldsJS, regEmailField, regPasswordField, registerPath)
	}

	return fmt.Sprintf(`import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  stages: %s,
  thresholds: {
    %s
  }
};

const BASE_URL = __ENV.BASE_URL || %q;

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
  return typeof curr === "string" ? curr : "";
}

export function setup() {
  const email = "k6-load-" + Date.now() + "-" + Math.floor(Math.random() * 100000) + "@example.com";
  const password = "K6LoadTest!2026#Secure";
  const jsonHeaders = { headers: { "Content-Type": "application/json" } };
%s  const loginPayload = { %q: email, %q: password };
  const loginRes = http.post(BASE_URL + %q, JSON.stringify(loginPayload), jsonHeaders);
  let token = "";
  try {
    const parsed = loginRes.json();
    token = extractPath(parsed, %q);
  } catch (_) {
    token = "";
  }
  return { token: token };
}

export default function (data) {
  const healthRes = http.get(BASE_URL + %q);
  check(healthRes, {
    "health status is 2xx": (r) => r.status >= 200 && r.status < 300,
  });
  if (data && data.token) {
    const meRes = http.get(BASE_URL + %q, {
      headers: { Authorization: "Bearer " + data.token },
    });
    check(meRes, {
      "me status is 2xx": (r) => r.status >= 200 && r.status < 300,
    });
  }
  sleep(0.1);
}
`, stagesJS, thresholdsJS, targetBase, registerBlock, loginEmailField, loginPasswordField, loginPath, tokenPath, healthPath, mePath)
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
