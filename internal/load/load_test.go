package load_test

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestAnalyzeMemoryPhases_DefeatsSawtoothGCAndIgnoresColdStartWarmup(t *testing.T) {
	const mib = 1024 * 1024
	baseTs := int64(1_700_000_000_000)

	makeSamples := func(rssMiBs []int64, stepMs int64, openFDs []int) []types.MemorySample {
		out := make([]types.MemorySample, len(rssMiBs))
		for i, mb := range rssMiBs {
			fd := 20
			if i < len(openFDs) {
				fd = openFDs[i]
			}
			out[i] = types.MemorySample{
				TimestampMs: baseTs + int64(i)*stepMs,
				RSSBytes:    mb * mib,
				OpenFDs:     fd,
			}
		}
		return out
	}

	t.Run("Case A Healthy Cold-Start Pool Warmup", func(t *testing.T) {
		// Warmup [0..4s]: 30 -> 38 -> 48 -> 49 -> 48 MiB (+60% vs t=0, last-3 warmup min = 48 MiB)
		// Sustained [5..15s]: oscillates 48..52..48 MiB
		// Cooldown (15..20s]: settles at 49 MiB
		rss := []int64{
			30, 38, 48, 49, 48,
			50, 52, 48, 51, 52, 48, 50, 52, 48, 51, 48,
			49, 49, 49, 49, 49,
		}
		samples := makeSamples(rss, 1000, nil)
		res := load.AnalyzeMemoryPhases(samples, nil, nil, load.MemoryAnalyzeOptions{
			WarmupDuration:          5 * time.Second,
			CooldownDuration:        5 * time.Second,
			TotalRequests:           5000,
			MaxRetainedDriftPercent: 15.0,
			MaxSlopeBytesPerReq:     1024.0,
			MaxFDGrowth:             32,
			MaxGoroutineGrowth:      32,
		})
		if res.LeakDetected {
			t.Fatalf("expected healthy cold-start warmup to pass without leak, got %+v", res)
		}
		if res.RetainedDriftPercent >= 5.0 {
			t.Fatalf("expected RetainedDriftPercent < 5%%, got %.2f%% (%+v)", res.RetainedDriftPercent, res)
		}
	})

	t.Run("Case B Sawtooth Memory Leak", func(t *testing.T) {
		// Warmup [0..1s]: 50 -> 50 MiB
		// Sustained [2..11s]: 50 -> 55 -> 60 -> 58 -> 64 -> 70 -> 67 -> 75 -> 82 -> 79 MiB
		// Cooldown (11..14s]: 79 -> 79 -> 79 MiB
		rss := []int64{
			50, 50,
			50, 55, 60, 58, 64, 70, 67, 75, 82, 79,
			79, 79, 79,
		}
		samples := makeSamples(rss, 1000, nil)
		res := load.AnalyzeMemoryPhases(samples, nil, nil, load.MemoryAnalyzeOptions{
			WarmupDuration:          2 * time.Second,
			CooldownDuration:        3 * time.Second,
			TotalRequests:           1000,
			MaxRetainedDriftPercent: 15.0,
			MaxSlopeBytesPerReq:     1024.0,
		})
		if !res.LeakDetected {
			t.Fatalf("expected sawtooth leak to be detected, got %+v", res)
		}
		if res.SlopeR2 <= 0.90 {
			t.Fatalf("expected SlopeR2 > 0.90 on rising GC floors, got %.4f (%+v)", res.SlopeR2, res)
		}
	})

	t.Run("Case C Short Zero-Variance Window", func(t *testing.T) {
		samples := []types.MemorySample{
			{TimestampMs: baseTs, RSSBytes: 40 * mib},
			{TimestampMs: baseTs, RSSBytes: 40 * mib},
		}
		res := load.AnalyzeMemoryPhases(samples, nil, nil, load.MemoryAnalyzeOptions{
			WarmupDuration:          5 * time.Second,
			CooldownDuration:        5 * time.Second,
			TotalRequests:           10,
			MaxRetainedDriftPercent: 15.0,
		})
		if res.LeakDetected {
			t.Fatalf("did not expect leak on identical samples, got %+v", res)
		}
		if math.IsNaN(res.SlopeBytesPerSec) || math.IsInf(res.SlopeBytesPerSec, 0) ||
			math.IsNaN(res.SlopeBytesPerReq) || math.IsInf(res.SlopeBytesPerReq, 0) ||
			math.IsNaN(res.SlopeR2) || math.IsInf(res.SlopeR2, 0) {
			t.Fatalf("expected finite regression metrics, got %+v", res)
		}
		b, err := json.Marshal(res)
		if err != nil || len(b) == 0 {
			t.Fatalf("expected clean json.Marshal without NaN/Inf, got err=%v", err)
		}
	})

	t.Run("Case D Goroutine and FD Leak with Flat RSS", func(t *testing.T) {
		rss := []int64{50, 50, 50, 50, 50, 50, 50, 50, 50, 50}
		fds := []int{20, 28, 36, 44, 52, 60, 70, 78, 86, 95}
		samples := makeSamples(rss, 1000, fds)
		preDiag := &types.RuntimeTelemetrySnapshot{Goroutines: 12, HeapInUseBytes: 20 * mib}
		postDiag := &types.RuntimeTelemetrySnapshot{Goroutines: 80, HeapInUseBytes: 20 * mib}

		res := load.AnalyzeMemoryPhases(samples, preDiag, postDiag, load.MemoryAnalyzeOptions{
			WarmupDuration:          2 * time.Second,
			CooldownDuration:        2 * time.Second,
			TotalRequests:           1000,
			MaxRetainedDriftPercent: 15.0,
			MaxFDGrowth:             32,
			MaxGoroutineGrowth:      32,
		})
		if !res.LeakDetected {
			t.Fatalf("expected FD/goroutine leak to set LeakDetected=true, got %+v", res)
		}
		if res.FDDelta != 75 || res.GoroutineDelta != 68 {
			t.Fatalf("expected FDDelta=75 and GoroutineDelta=68, got %+v", res)
		}
	})
}

func TestGenerateK6Script_MultiScenarioCapabilities(t *testing.T) {
	m, err := manifest.ParseAndValidateManifest([]byte(`{
		"name": "full-capabilities-api",
		"language": "go",
		"capabilities": {
			"health": { "method": "GET", "path": "/healthz" },
			"auth": {
				"register": { "method": "POST", "path": "/auth/register" },
				"login": { "method": "POST", "path": "/auth/login", "tokenPath": "accessToken", "refreshPath": "refreshToken" },
				"me": { "method": "GET", "path": "/auth/me" },
				"refresh": { "method": "POST", "path": "/auth/refresh" }
			},
			"crud": {
				"collectionPath": "/items",
				"itemPath": "/items/{id}",
				"idPath": "id",
				"sampleCreateBody": { "title": "conformance-item" }
			},
			"websockets": { "enabled": true, "path": "/ws" }
		}
	}`))
	if err != nil {
		t.Fatalf("ParseAndValidateManifest failed: %v", err)
	}

	script := load.GenerateK6Script(m, "http://127.0.0.1:3000", load.ProfileSoak)
	for _, want := range []string{
		"scenarios:",
		"read_steady",
		"crud_lifecycle",
		"auth_session_churn",
		"ws_churn",
		"error_abort_paths",
		`import ws from "k6/ws"`,
		"/items",
		"http.patch",
		"http.del",
		"/auth/refresh",
		"/ws",
		"p(95)<300",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("expected multi-scenario k6 script to contain %q, got:\n%s", want, script)
		}
	}
}

func TestCgroupV2LsofAndDiagnosticsSnapshot(t *testing.T) {
	rawCgroup := "104857600\nanon 52428800\nfile 41943040\ninactive_file 20971520\n"
	cur, ws, ok := load.ParseCgroupV2Memory(rawCgroup)
	if !ok || cur != 104857600 || ws != 83886080 {
		t.Fatalf("ParseCgroupV2Memory unexpected result: cur=%d ws=%d ok=%v", cur, ws, ok)
	}

	rawLsof := strings.Join([]string{
		"COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME",
		"api 42 root 10u IPv4 0x1 0t0 TCP 127.0.0.1:8080 (LISTEN)",
		"api 42 root 11u IPv4 0x2 0t0 TCP 127.0.0.1:50000->127.0.0.1:5432 (ESTABLISHED)",
		"api 42 root 12u IPv4 0x3 0t0 TCP 127.0.0.1:50001->10.0.0.5:80 (CLOSE_WAIT)",
		"api 42 root 13u IPv4 0x4 0t0 TCP 127.0.0.1:50002->10.0.0.6:80 (CLOSE_WAIT)",
	}, "\n")
	fds, cw := load.ParseLsofFDsAndCloseWait(rawLsof)
	if fds != 4 || cw != 2 {
		t.Fatalf("expected openFDs=4 closeWait=2, got fds=%d cw=%d", fds, cw)
	}

	var gcTriggered bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/debug/gc":
			if r.Method == http.MethodPost {
				gcTriggered = true
			}
			w.WriteHeader(http.StatusOK)
		case "/debug/pprof/goroutine":
			_, _ = w.Write([]byte("goroutine profile: total 42\n1 @ 0x1\n"))
		case "/debug/pprof/heap":
			_, _ = w.Write([]byte("heap profile: 320: 1048576 [640: 2097152] @ heap/1048576\n# runtime.MemStats\n# HeapInuse = 1048576\n# HeapObjects = 320\n"))
		case "/debug/stats":
			_, _ = w.Write([]byte(`{"v8UsedHeapBytes":2097152,"activeHandles":7,"beamAtomBytes":65536}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	diag := &types.DiagnosticsCapability{
		Enabled:         true,
		PprofBaseURL:    srv.URL + "/debug/pprof",
		RuntimeStatsURL: srv.URL + "/debug/stats",
		GCTriggerURL:    srv.URL + "/debug/gc",
	}
	if !load.TriggerDiagnosticsGC(context.Background(), diag) || !gcTriggered {
		t.Fatalf("expected TriggerDiagnosticsGC to POST %s", diag.GCTriggerURL)
	}
	snap := load.PollDiagnosticsSnapshot(context.Background(), diag)
	if snap == nil {
		t.Fatalf("expected non-nil DiagnosticsSnapshot")
	}
	if snap.Goroutines != 42 || snap.HeapInUseBytes != 1048576 || snap.HeapObjects != 320 || snap.V8UsedHeapBytes != 2097152 || snap.ActiveHandles != 7 || snap.BeamAtomBytes != 65536 {
		t.Fatalf("unexpected diagnostics snapshot: %+v", snap)
	}
}
