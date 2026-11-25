package load_test

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/load"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/manifest"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/runner"
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

func TestRunK6LoadTest_DockerReadablePermissions(t *testing.T) {
	m, _ := manifest.ParseAndValidateManifest([]byte(`{
  "name": "node-api",
  "language": "typescript",
  "capabilities": { "health": { "method": "GET", "path": "/health/live" } }
}`))

	mockExec := func(ctx context.Context, cmd runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		scriptPath := cmd.Args[len(cmd.Args)-1]
		workDir := filepath.Dir(scriptPath)
		dirInfo, err := os.Stat(workDir)
		if err != nil {
			return runner.ToolExecutionResult{}, err
		}
		if dirInfo.Mode().Perm()&0o007 != 0o007 {
			t.Fatalf("expected WorkDir %s to be world-writable/readable/executable for docker k6 user, got %o", workDir, dirInfo.Mode().Perm())
		}
		parentInfo, err := os.Stat(filepath.Dir(workDir))
		if err != nil {
			return runner.ToolExecutionResult{}, err
		}
		if parentInfo.Mode().Perm() != 0o700 {
			t.Fatalf("expected parent of WorkDir %s to be isolated 0700, got %o", workDir, parentInfo.Mode().Perm())
		}
		scriptInfo, err := os.Stat(scriptPath)
		if err != nil {
			return runner.ToolExecutionResult{}, err
		}
		if scriptInfo.Mode().Perm()&0o004 == 0 {
			t.Fatalf("expected load.js to be world-readable for docker k6 user, got %o", scriptInfo.Mode().Perm())
		}
		summary := `{"metrics":{"http_req_duration":{"p(95)":10,"p(99)":20,"avg":5},"http_reqs":{"count":10,"rate":10},"http_req_failed":{"value":0}}}`
		if err := os.WriteFile(filepath.Join(workDir, "summary.json"), []byte(summary), 0o644); err != nil {
			return runner.ToolExecutionResult{}, err
		}
		return runner.ToolExecutionResult{ExitCode: 0, OK: true, Mode: cmd.Mode}, nil
	}

	_, err := load.RunK6LoadTest(context.Background(), m, "http://127.0.0.1:3000", load.ProfileBaseline, runner.ModeLocal, mockExec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := load.SampleDockerContainerMemory(context.Background(), "", 0, 20.0); got != nil {
		t.Fatalf("expected nil memory analysis when container name is empty, got %+v", got)
	}
}

func TestGenerateK6Script_AuthenticatedMultiEndpointMix(t *testing.T) {
	m, err := manifest.ParseAndValidateManifest([]byte(`{
		"name": "auth-api",
		"language": "typescript",
		"capabilities": {
			"health": { "path": "/health/live" },
			"auth": {
				"register": { "path": "/auth/register" },
				"login": { "path": "/auth/login", "tokenPath": "data.accessToken" },
				"me": { "path": "/auth/me" }
			}
		}
	}`))
	if err != nil {
		t.Fatalf("ParseAndValidateManifest failed: %v", err)
	}
	script := load.GenerateK6Script(m, "http://127.0.0.1:3000", load.ProfileBaseline)
	for _, want := range []string{"export function setup()", "/auth/register", "/auth/login", "/auth/me", "Authorization"} {
		if !strings.Contains(script, want) {
			t.Fatalf("expected authenticated k6 script to contain %q, got:\n%s", want, script)
		}
	}
}

func TestGenerateK6Script_SetupThrowsOnTokenFailure(t *testing.T) {
	mAuth, err := manifest.ParseAndValidateManifest([]byte(`{
		"name": "auth-fail-closed-api",
		"language": "go",
		"capabilities": {
			"health": { "path": "/health" },
			"auth": {
				"register": { "path": "/auth/register" },
				"login": { "path": "/auth/login", "tokenPath": "data.accessToken" },
				"me": { "path": "/auth/me" }
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	authScript := load.GenerateK6Script(mAuth, "http://127.0.0.1:3000", load.ProfileBaseline)
	for _, want := range []string{
		`if (loginRes.status < 200 || loginRes.status >= 300 || !token)`,
		`throw new Error("k6 setup failed: unable to acquire bearer token from `,
	} {
		if !strings.Contains(authScript, want) {
			t.Fatalf("expected authenticated k6 script setup() to contain %q so auth failures abort run, got:\n%s", want, authScript)
		}
	}

	mHealth, err := manifest.ParseAndValidateManifest([]byte(`{
		"name": "health-only-api",
		"language": "go",
		"capabilities": {
			"health": { "path": "/health" }
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	healthScript := load.GenerateK6Script(mHealth, "http://127.0.0.1:3000", load.ProfileBaseline)
	if strings.Contains(healthScript, "k6 setup failed") {
		t.Fatalf("did not expect health-only k6 script to contain auth setup error throw, got:\n%s", healthScript)
	}
}
