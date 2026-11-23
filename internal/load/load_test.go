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
