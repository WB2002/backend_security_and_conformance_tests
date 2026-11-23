package load

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

var memTokenRe = regexp.MustCompile(`(?i)^\s*([0-9]+(?:\.[0-9]+)?)\s*(b|kib|kb|mib|mb|gib|gb)\b`)

func ParseDockerMemUsageBytes(memUsageField string) (int64, error) {
	firstPart := strings.Split(memUsageField, "/")[0]
	m := memTokenRe.FindStringSubmatch(strings.TrimSpace(firstPart))
	if len(m) != 3 {
		return 0, fmt.Errorf("invalid docker memory usage string %q", memUsageField)
	}
	val, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, err
	}
	unit := strings.ToLower(m[2])
	var mult float64 = 1
	switch unit {
	case "kib":
		mult = 1024
	case "kb":
		mult = 1000
	case "mib":
		mult = 1024 * 1024
	case "mb":
		mult = 1000 * 1000
	case "gib":
		mult = 1024 * 1024 * 1024
	case "gb":
		mult = 1000 * 1000 * 1000
	}
	return int64(val * mult), nil
}

func AnalyzeMemorySamples(samples []types.MemorySample, maxAllowedDriftPercent float64) types.MemoryLeakAnalysis {
	if len(samples) == 0 {
		return types.MemoryLeakAnalysis{}
	}
	initial := samples[0].RSSBytes
	final := samples[len(samples)-1].RSSBytes
	peak := initial
	nonDecreasingSteps := 0

	for i, s := range samples {
		if s.RSSBytes > peak {
			peak = s.RSSBytes
		}
		if i > 0 && s.RSSBytes >= samples[i-1].RSSBytes {
			nonDecreasingSteps++
		}
	}

	var drift float64
	if initial > 0 {
		drift = (float64(final-initial) / float64(initial)) * 100.0
	}

	monotonicGrowth := len(samples) >= 3 && float64(nonDecreasingSteps)/float64(len(samples)-1) >= 0.75
	leakDetected := drift > maxAllowedDriftPercent && monotonicGrowth

	return types.MemoryLeakAnalysis{
		InitialRSSBytes: initial,
		FinalRSSBytes:   final,
		PeakRSSBytes:    peak,
		DriftPercent:    drift,
		LeakDetected:    leakDetected,
		Samples:         samples,
	}
}

func SampleDockerContainerMemory(ctx context.Context, interval time.Duration, maxDriftPercent float64) *types.MemoryLeakAnalysis {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil
	}
	var samples []types.MemorySample
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	collectOnce := func() {
		out, err := exec.CommandContext(ctx, "docker", "stats", "--no-stream", "--format", "{{.MemUsage}}\t{{.CPUPerc}}").Output()
		if err != nil {
			return
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) == 0 || lines[0] == "" {
			return
		}
		parts := strings.Split(lines[0], "\t")
		rss, err := ParseDockerMemUsageBytes(parts[0])
		if err != nil || rss <= 0 {
			return
		}
		var cpu float64
		if len(parts) > 1 {
			cpu, _ = strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(parts[1]), "%"), 64)
		}
		samples = append(samples, types.MemorySample{
			TimestampMs: time.Now().UnixMilli(),
			RSSBytes:    rss,
			CPUPercent:  cpu,
		})
	}

	collectOnce()
	for {
		select {
		case <-ctx.Done():
			collectOnce()
			if len(samples) == 0 {
				return nil
			}
			res := AnalyzeMemorySamples(samples, maxDriftPercent)
			return &res
		case <-ticker.C:
			collectOnce()
		}
	}
}

