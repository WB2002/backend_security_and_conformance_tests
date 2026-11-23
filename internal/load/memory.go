package load

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

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
