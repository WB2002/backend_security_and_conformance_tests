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

func GenerateK6Script(m types.BoilerplateManifest, baseURL string, profile LoadProfile) string {
	targetBase := strings.TrimRight(baseURL, "/")
	healthPath := m.Capabilities.Health.Path
	if !strings.HasPrefix(healthPath, "/") {
		healthPath = "/" + healthPath
	}

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
	tmpDir, err := os.MkdirTemp("", "k6-conformance-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	targetBase := baseURL
	if mode == runner.ModeDocker {
		targetBase = runner.RewriteURLForDocker(baseURL)
	}

	scriptContent := GenerateK6Script(m, targetBase, profile)
	scriptPath := filepath.Join(tmpDir, "load.js")
	summaryPath := filepath.Join(tmpDir, "summary.json")
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0600); err != nil {
		return nil, err
	}

	argScript := scriptPath
	argSummary := summaryPath
	if mode == runner.ModeDocker {
		argScript = "/out/load.js"
		argSummary = "/out/summary.json"
	}

	_, err = runner.RunTool(ctx, runner.ToolInvocationOptions{
		Tool:             runner.ToolK6,
		Args:             []string{"run", "--summary-export", argSummary, argScript},
		WorkDir:          tmpDir,
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
	return &s, nil
}
