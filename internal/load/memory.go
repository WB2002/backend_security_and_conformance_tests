package load

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

var (
	memTokenRe           = regexp.MustCompile(`(?i)^\s*([0-9]+(?:\.[0-9]+)?)\s*(b|kib|kb|mib|mb|gib|gb)\b`)
	pprofGoroutineTotal  = regexp.MustCompile(`(?m)^goroutine profile:\s+total\s+(\d+)`)
	pprofGoroutineHeader = regexp.MustCompile(`(?m)^goroutine\s+\d+\s+\[`)
	pprofHeapProfileRe   = regexp.MustCompile(`(?m)^heap profile:\s*(\d+):\s*(\d+)`)
	pprofMemStatsInuseRe = regexp.MustCompile(`(?m)^#\s*HeapInuse\s*=\s*(\d+)`)
	pprofMemStatsObjsRe  = regexp.MustCompile(`(?m)^#\s*HeapObjects\s*=\s*(\d+)`)
)

// MemoryAnalyzeOptions configures 3-phase GC-aware memory, FD, and runtime leak analysis.
type MemoryAnalyzeOptions struct {
	WarmupDuration          time.Duration
	CooldownDuration        time.Duration
	TotalRequests           int64
	MaxRetainedDriftPercent float64
	MaxSlopeBytesPerReq     float64
	MaxFDGrowth             int
	MaxGoroutineGrowth      int
}

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

// ParseCgroupV2Memory parses concatenated `/sys/fs/cgroup/memory.current` and
// `/sys/fs/cgroup/memory.stat` output, returning current RSS bytes and working-set
// bytes (`memory.current - inactive_file`).
func ParseCgroupV2Memory(raw string) (currentBytes int64, workingSetBytes int64, ok bool) {
	lines := strings.Split(raw, "\n")
	parsedCurrent := false
	var inactiveFile int64

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !parsedCurrent {
			val, err := strconv.ParseInt(trimmed, 10, 64)
			if err != nil || val <= 0 {
				return 0, 0, false
			}
			currentBytes = val
			parsedCurrent = true
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[0] == "inactive_file" {
			if val, err := strconv.ParseInt(fields[1], 10, 64); err == nil && val >= 0 {
				inactiveFile = val
			}
		}
	}
	if !parsedCurrent {
		return 0, 0, false
	}
	workingSetBytes = currentBytes - inactiveFile
	if workingSetBytes < 0 {
		workingSetBytes = 0
	}
	return currentBytes, workingSetBytes, true
}

// ParseLsofFDsAndCloseWait counts open file descriptors and CLOSE_WAIT sockets from `lsof -nP -p <pid>`.
func ParseLsofFDsAndCloseWait(raw string) (openFDs int, closeWait int) {
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "COMMAND") {
			continue
		}
		openFDs++
		if strings.Contains(trimmed, "(CLOSE_WAIT)") {
			closeWait++
		}
	}
	return openFDs, closeWait
}

// ParseProcNetCloseWait counts sockets in TCP_CLOSE_WAIT (state 08) in `/proc/net/tcp` and `/proc/net/tcp6`.
func ParseProcNetCloseWait(rawTCP, rawTCP6 string) int {
	count := 0
	for _, table := range []string{rawTCP, rawTCP6} {
		for _, line := range strings.Split(table, "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 4 && fields[0] != "sl" && strings.EqualFold(fields[3], "08") {
				count++
			}
		}
	}
	return count
}

func effectiveSampleMem(s types.MemorySample) int64 {
	if s.WorkingSetBytes > 0 {
		return s.WorkingSetBytes
	}
	return s.RSSBytes
}

func minEffectiveMem(samples []types.MemorySample) int64 {
	if len(samples) == 0 {
		return 0
	}
	best := effectiveSampleMem(samples[0])
	for _, s := range samples[1:] {
		if v := effectiveSampleMem(s); v < best {
			best = v
		}
	}
	return best
}

func finiteFloat(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

func splitMemoryPhases(sorted []types.MemorySample, warmupDur, cooldownDur time.Duration) (warmup, sustained, cooldown []types.MemorySample) {
	if len(sorted) == 0 {
		return nil, nil, nil
	}
	if warmupDur < 0 {
		warmupDur = 0
	}
	if cooldownDur < 0 {
		cooldownDur = 0
	}
	t0 := sorted[0].TimestampMs
	tEnd := sorted[len(sorted)-1].TimestampMs
	warmupEnd := t0 + warmupDur.Milliseconds()
	cooldownStart := tEnd - cooldownDur.Milliseconds()

	if warmupEnd < cooldownStart {
		for _, s := range sorted {
			switch {
			case s.TimestampMs < warmupEnd:
				warmup = append(warmup, s)
			case s.TimestampMs > cooldownStart:
				cooldown = append(cooldown, s)
			default:
				sustained = append(sustained, s)
			}
		}
	}
	if len(sustained) < 2 {
		sustained = sorted
	}
	return warmup, sustained, cooldown
}

func extractGCFloorMinima(sustained []types.MemorySample) []types.MemorySample {
	if len(sustained) < 2 {
		return sustained
	}
	var minima []types.MemorySample
	for i := 1; i < len(sustained)-1; i++ {
		cur := effectiveSampleMem(sustained[i])
		prev := effectiveSampleMem(sustained[i-1])
		next := effectiveSampleMem(sustained[i+1])
		if cur <= prev && cur <= next {
			minima = append(minima, sustained[i])
		}
	}
	if len(minima) < 2 {
		// Fall back to endpoints alongside any single interior floor minimum.
		out := make([]types.MemorySample, 0, len(minima)+2)
		out = append(out, sustained[0])
		out = append(out, minima...)
		out = append(out, sustained[len(sustained)-1])
		return out
	}
	return minima
}

func computeOLSRegression(floors, sustained []types.MemorySample, totalRequests int64) (slopePerSec, slopePerReq, r2 float64) {
	if len(floors) < 2 {
		return 0, 0, 0
	}
	tBase := floors[0].TimestampMs
	xs := make([]float64, len(floors))
	ys := make([]float64, len(floors))
	var sumX, sumY float64
	for i, s := range floors {
		xs[i] = float64(s.TimestampMs-tBase) / 1000.0
		ys[i] = float64(effectiveSampleMem(s))
		sumX += xs[i]
		sumY += ys[i]
	}
	n := float64(len(floors))
	meanX := sumX / n
	meanY := sumY / n

	var ssXX, ssXY, ssYY float64
	for i := range floors {
		dx := xs[i] - meanX
		dy := ys[i] - meanY
		ssXX += dx * dx
		ssXY += dx * dy
		ssYY += dy * dy
	}
	if ssXX <= 0 {
		return 0, 0, 0
	}
	slopePerSec = finiteFloat(ssXY / ssXX)
	if ssYY > 0 {
		intercept := meanY - slopePerSec*meanX
		var ssRes float64
		for i := range floors {
			pred := slopePerSec*xs[i] + intercept
			diff := ys[i] - pred
			ssRes += diff * diff
		}
		r2 = finiteFloat(1.0 - (ssRes / ssYY))
		if r2 < 0 {
			r2 = 0
		} else if r2 > 1 {
			r2 = 1
		}
	}

	var sustainedSec float64
	if len(sustained) >= 2 {
		sustainedSec = float64(sustained[len(sustained)-1].TimestampMs-sustained[0].TimestampMs) / 1000.0
		if sustainedSec < 0 {
			sustainedSec = 0
		}
	}
	reqs := totalRequests
	if reqs < 1 {
		reqs = 1
	}
	slopePerReq = finiteFloat((slopePerSec * sustainedSec) / float64(reqs))
	return slopePerSec, slopePerReq, r2
}

// AnalyzeMemoryPhases splits soak telemetry into warmup, sustained, and cooldown windows,
// extracts sustained GC floor minima for OLS trend regression, and evaluates memory/FD/runtime leak gates.
func AnalyzeMemoryPhases(
	samples []types.MemorySample,
	preDiag, postDiag *types.RuntimeTelemetrySnapshot,
	opts MemoryAnalyzeOptions,
) types.MemoryLeakAnalysis {
	var goroutineDelta int
	var heapInUseDelta, beamAtomDelta int64
	if preDiag != nil && postDiag != nil {
		goroutineDelta = postDiag.Goroutines - preDiag.Goroutines
		heapInUseDelta = postDiag.HeapInUseBytes - preDiag.HeapInUseBytes
		beamAtomDelta = postDiag.BeamAtomBytes - preDiag.BeamAtomBytes
	}

	if len(samples) == 0 {
		leak := (opts.MaxGoroutineGrowth > 0 && goroutineDelta > opts.MaxGoroutineGrowth) ||
			(beamAtomDelta > 1024*1024)
		return types.MemoryLeakAnalysis{
			LeakDetected:        leak,
			GoroutineDelta:      goroutineDelta,
			HeapInUseDeltaBytes: heapInUseDelta,
			BeamAtomDeltaBytes:  beamAtomDelta,
			PreSoakDiag:         preDiag,
			PostCooldownDiag:    postDiag,
		}
	}

	sorted := slices.Clone(samples)
	slices.SortStableFunc(sorted, func(a, b types.MemorySample) int {
		return cmp.Compare(a.TimestampMs, b.TimestampMs)
	})

	initial := effectiveSampleMem(sorted[0])
	final := effectiveSampleMem(sorted[len(sorted)-1])
	peak := initial
	for _, s := range sorted {
		if m := effectiveSampleMem(s); m > peak {
			peak = m
		}
	}
	var drift float64
	if initial > 0 {
		drift = finiteFloat((float64(final-initial) / float64(initial)) * 100.0)
	}

	warmup, sustained, cooldown := splitMemoryPhases(sorted, opts.WarmupDuration, opts.CooldownDuration)

	var postWarmupBaseline int64
	if len(warmup) > 0 {
		tail := warmup
		if len(tail) > 3 {
			tail = tail[len(tail)-3:]
		}
		postWarmupBaseline = minEffectiveMem(tail)
	} else {
		postWarmupBaseline = effectiveSampleMem(sustained[0])
	}

	var postCooldownRSS int64
	if len(cooldown) > 0 {
		postCooldownRSS = minEffectiveMem(cooldown)
	} else {
		postCooldownRSS = effectiveSampleMem(sustained[len(sustained)-1])
	}

	var retainedDrift float64
	if postWarmupBaseline > 0 {
		retainedDrift = finiteFloat((float64(postCooldownRSS-postWarmupBaseline) / float64(postWarmupBaseline)) * 100.0)
	}

	floors := extractGCFloorMinima(sustained)
	slopePerSec, slopePerReq, slopeR2 := computeOLSRegression(floors, sustained, opts.TotalRequests)

	fdDelta := sorted[len(sorted)-1].OpenFDs - sorted[0].OpenFDs
	closeWaitDelta := sorted[len(sorted)-1].CloseWaitSockets - sorted[0].CloseWaitSockets

	leakDetected := (retainedDrift > opts.MaxRetainedDriftPercent && slopePerSec > 0 && slopeR2 >= 0.55) ||
		(opts.MaxSlopeBytesPerReq > 0 && slopePerReq > opts.MaxSlopeBytesPerReq && slopeR2 >= 0.65) ||
		(opts.MaxFDGrowth > 0 && fdDelta > opts.MaxFDGrowth) ||
		(opts.MaxGoroutineGrowth > 0 && goroutineDelta > opts.MaxGoroutineGrowth) ||
		(beamAtomDelta > 1024*1024)

	return types.MemoryLeakAnalysis{
		InitialRSSBytes:         initial,
		FinalRSSBytes:           final,
		PeakRSSBytes:            peak,
		DriftPercent:            drift,
		LeakDetected:            leakDetected,
		PostWarmupBaselineBytes: postWarmupBaseline,
		PostCooldownRSSBytes:    postCooldownRSS,
		RetainedDriftPercent:    retainedDrift,
		SlopeBytesPerSec:        slopePerSec,
		SlopeBytesPerReq:        slopePerReq,
		SlopeR2:                 slopeR2,
		FDDelta:                 fdDelta,
		CloseWaitDelta:          closeWaitDelta,
		GoroutineDelta:          goroutineDelta,
		HeapInUseDeltaBytes:     heapInUseDelta,
		BeamAtomDeltaBytes:      beamAtomDelta,
		PreSoakDiag:             preDiag,
		PostCooldownDiag:        postDiag,
		Samples:                 sorted,
	}
}

func AnalyzeMemorySamples(samples []types.MemorySample, maxAllowedDriftPercent float64) types.MemoryLeakAnalysis {
	if len(samples) == 0 {
		return types.MemoryLeakAnalysis{}
	}
	initial := effectiveSampleMem(samples[0])
	final := effectiveSampleMem(samples[len(samples)-1])
	peak := initial
	nonDecreasingSteps := 0

	for i, s := range samples {
		cur := effectiveSampleMem(s)
		if cur > peak {
			peak = cur
		}
		if i > 0 && cur >= effectiveSampleMem(samples[i-1]) {
			nonDecreasingSteps++
		}
	}

	var drift float64
	if initial > 0 {
		drift = finiteFloat((float64(final-initial) / float64(initial)) * 100.0)
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

func collectDockerMemorySample(ctx context.Context, containerName string) (types.MemorySample, bool) {
	var rss, workingSet int64
	var cpu float64

	if cgOut, err := exec.CommandContext(ctx, "docker", "exec", containerName, "cat", "/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.stat").Output(); err == nil {
		if cur, ws, ok := ParseCgroupV2Memory(string(cgOut)); ok {
			rss = cur
			workingSet = ws
		}
	}

	if statsOut, err := exec.CommandContext(ctx, "docker", "stats", "--no-stream", "--format", "{{.MemUsage}}\t{{.CPUPerc}}", containerName).Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(statsOut)), "\n")
		if len(lines) > 0 && lines[0] != "" {
			parts := strings.Split(lines[0], "\t")
			if rss == 0 {
				if parsedRSS, pErr := ParseDockerMemUsageBytes(parts[0]); pErr == nil && parsedRSS > 0 {
					rss = parsedRSS
				}
			}
			if len(parts) > 1 {
				cpu, _ = strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(parts[1]), "%"), 64)
			}
		}
	}

	if rss <= 0 && workingSet <= 0 {
		return types.MemorySample{}, false
	}

	var openFDs, closeWait int
	if fdOut, err := exec.CommandContext(ctx, "docker", "exec", containerName, "sh", "-c", "ls -1 /proc/1/fd 2>/dev/null | wc -l").Output(); err == nil {
		openFDs, _ = strconv.Atoi(strings.TrimSpace(string(fdOut)))
	}
	tcpOut, _ := exec.CommandContext(ctx, "docker", "exec", containerName, "cat", "/proc/net/tcp", "/proc/net/tcp6").Output()
	if len(tcpOut) > 0 {
		closeWait = ParseProcNetCloseWait(string(tcpOut), "")
	}

	return types.MemorySample{
		TimestampMs:      time.Now().UnixMilli(),
		RSSBytes:         rss,
		WorkingSetBytes:  workingSet,
		CPUPercent:       cpu,
		OpenFDs:          openFDs,
		CloseWaitSockets: closeWait,
	}, true
}

func collectProcessMemorySample(ctx context.Context, pid int) (types.MemorySample, bool) {
	pidStr := strconv.Itoa(pid)
	out, err := exec.CommandContext(ctx, "ps", "-o", "rss=,%cpu=", "-p", pidStr).Output()
	if err != nil {
		return types.MemorySample{}, false
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) == 0 {
		return types.MemorySample{}, false
	}
	rssKiB, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || rssKiB <= 0 {
		return types.MemorySample{}, false
	}
	var cpu float64
	if len(fields) > 1 {
		cpu, _ = strconv.ParseFloat(fields[1], 64)
	}

	var openFDs, closeWait int
	if entries, fdErr := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid)); fdErr == nil {
		openFDs = len(entries)
		raw4, _ := os.ReadFile(fmt.Sprintf("/proc/%d/net/tcp", pid))
		raw6, _ := os.ReadFile(fmt.Sprintf("/proc/%d/net/tcp6", pid))
		closeWait = ParseProcNetCloseWait(string(raw4), string(raw6))
	} else if _, lsofErr := exec.LookPath("lsof"); lsofErr == nil {
		if lsofOut, err := exec.CommandContext(ctx, "lsof", "-nP", "-p", pidStr).Output(); err == nil {
			openFDs, closeWait = ParseLsofFDsAndCloseWait(string(lsofOut))
		}
	}

	return types.MemorySample{
		TimestampMs:      time.Now().UnixMilli(),
		RSSBytes:         rssKiB * 1024,
		CPUPercent:       cpu,
		OpenFDs:          openFDs,
		CloseWaitSockets: closeWait,
	}, true
}

// StartMemorySampler polls process or container memory, working-set, open FDs, and CLOSE_WAIT sockets
// until ctx is cancelled, returning the collected sample slice on the returned channel.
func StartMemorySampler(ctx context.Context, pid int, containerName string, interval time.Duration) <-chan []types.MemorySample {
	outCh := make(chan []types.MemorySample, 1)
	containerName = strings.TrimSpace(containerName)
	if pid <= 0 && containerName == "" {
		outCh <- nil
		close(outCh)
		return outCh
	}
	if interval <= 0 {
		interval = time.Second
	}
	if ctx == nil {
		ctx = context.Background()
	}

	go func() {
		defer close(outCh)
		var samples []types.MemorySample
		collectOnce := func(c context.Context) {
			pctx, cancel := context.WithTimeout(c, 3*time.Second)
			defer cancel()
			if containerName != "" {
				if s, ok := collectDockerMemorySample(pctx, containerName); ok {
					samples = append(samples, s)
				}
				return
			}
			if s, ok := collectProcessMemorySample(pctx, pid); ok {
				samples = append(samples, s)
			}
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		collectOnce(ctx)
		for {
			select {
			case <-ctx.Done():
				collectOnce(context.Background())
				outCh <- samples
				return
			case <-ticker.C:
				collectOnce(ctx)
			}
		}
	}()
	return outCh
}

func SampleDockerContainerMemory(ctx context.Context, containerName string, interval time.Duration, maxDriftPercent float64) *types.MemoryLeakAnalysis {
	containerName = strings.TrimSpace(containerName)
	if containerName == "" {
		return nil
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return nil
	}
	samples := <-StartMemorySampler(ctx, 0, containerName, interval)
	if len(samples) == 0 {
		return nil
	}
	res := AnalyzeMemorySamples(samples, maxDriftPercent)
	return &res
}

func SampleProcessMemory(ctx context.Context, pid int, interval time.Duration, maxDriftPercent float64) *types.MemoryLeakAnalysis {
	if pid <= 0 {
		return nil
	}
	if _, err := exec.LookPath("ps"); err != nil {
		return nil
	}
	samples := <-StartMemorySampler(ctx, pid, "", interval)
	if len(samples) == 0 {
		return nil
	}
	res := AnalyzeMemorySamples(samples, maxDriftPercent)
	return &res
}

func fetchDiagBody(ctx context.Context, client *http.Client, targetURL string) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, false
	}
	return data, true
}

func buildPprofEndpoint(base, suffix string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(base), "/")
	if strings.HasSuffix(trimmed, "/debug/pprof") {
		return trimmed + "/" + suffix
	}
	return trimmed + "/debug/pprof/" + suffix
}

func parsePprofTelemetry(goroutineRaw, heapRaw []byte, snap *types.RuntimeTelemetrySnapshot) {
	if len(goroutineRaw) > 0 {
		s := string(goroutineRaw)
		if m := pprofGoroutineTotal.FindStringSubmatch(s); len(m) > 1 {
			if n, err := strconv.Atoi(m[1]); err == nil {
				snap.Goroutines = n
			}
		} else if headers := pprofGoroutineHeader.FindAllStringIndex(s, -1); len(headers) > 0 {
			snap.Goroutines = len(headers)
		}
	}
	if len(heapRaw) > 0 {
		s := string(heapRaw)
		if m := pprofHeapProfileRe.FindStringSubmatch(s); len(m) > 2 {
			if objs, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				snap.HeapObjects = objs
			}
			if bytesVal, err := strconv.ParseInt(m[2], 10, 64); err == nil {
				snap.HeapInUseBytes = bytesVal
			}
		}
		if m := pprofMemStatsInuseRe.FindStringSubmatch(s); len(m) > 1 {
			if bytesVal, err := strconv.ParseInt(m[1], 10, 64); err == nil && snap.HeapInUseBytes == 0 {
				snap.HeapInUseBytes = bytesVal
			}
		}
		if m := pprofMemStatsObjsRe.FindStringSubmatch(s); len(m) > 1 {
			if objs, err := strconv.ParseInt(m[1], 10, 64); err == nil && snap.HeapObjects == 0 {
				snap.HeapObjects = objs
			}
		}
	}
}

func applyRuntimeStatsJSON(raw []byte, snap *types.RuntimeTelemetrySnapshot) bool {
	if len(raw) == 0 {
		return false
	}
	if err := json.Unmarshal(raw, snap); err != nil {
		return false
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return true
	}
	int64Field := func(keys ...string) int64 {
		for _, k := range keys {
			if v, ok := m[k].(float64); ok {
				return int64(v)
			}
		}
		return 0
	}
	if snap.V8UsedHeapBytes == 0 {
		snap.V8UsedHeapBytes = int64Field("v8_used_heap_bytes", "heapUsed")
	}
	if snap.ActiveHandles == 0 {
		snap.ActiveHandles = int(int64Field("active_handles"))
	}
	if snap.PyTracemallocBytes == 0 {
		snap.PyTracemallocBytes = int64Field("py_tracemalloc_bytes", "tracemallocCurrentBytes")
	}
	if snap.PyAsyncTasks == 0 {
		snap.PyAsyncTasks = int(int64Field("py_async_tasks", "asyncTasks"))
	}
	if snap.BeamProcessCount == 0 {
		snap.BeamProcessCount = int(int64Field("beam_process_count", "processCount"))
	}
	if snap.BeamAtomBytes == 0 {
		snap.BeamAtomBytes = int64Field("beam_atom_bytes", "atomBytes")
	}
	if snap.BeamBinaryBytes == 0 {
		snap.BeamBinaryBytes = int64Field("beam_binary_bytes", "binaryBytes")
	}
	if snap.BeamETSBytes == 0 {
		snap.BeamETSBytes = int64Field("beam_ets_bytes", "etsBytes")
	}
	return true
}

// TriggerDiagnosticsGC sends an optional POST to diag.GCTriggerURL before cooldown sampling.
func TriggerDiagnosticsGC(ctx context.Context, diag *types.DiagnosticsCapability) bool {
	if diag == nil || !diag.Enabled || strings.TrimSpace(diag.GCTriggerURL) == "" {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(diag.GCTriggerURL), nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// PollDiagnosticsSnapshot collects Go pprof goroutine/heap metrics and/or polyglot
// runtime telemetry JSON from the target's configured diagnostics endpoints.
func PollDiagnosticsSnapshot(ctx context.Context, diag *types.DiagnosticsCapability) *types.RuntimeTelemetrySnapshot {
	if diag == nil || !diag.Enabled {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	client := &http.Client{Timeout: 3 * time.Second}
	var snap types.RuntimeTelemetrySnapshot
	populated := false

	if strings.TrimSpace(diag.PprofBaseURL) != "" {
		gBody, gOK := fetchDiagBody(ctx, client, buildPprofEndpoint(diag.PprofBaseURL, "goroutine?debug=1"))
		hBody, hOK := fetchDiagBody(ctx, client, buildPprofEndpoint(diag.PprofBaseURL, "heap?debug=1"))
		if gOK || hOK {
			parsePprofTelemetry(gBody, hBody, &snap)
			populated = true
		}
	}

	if strings.TrimSpace(diag.RuntimeStatsURL) != "" {
		if statsBody, ok := fetchDiagBody(ctx, client, strings.TrimSpace(diag.RuntimeStatsURL)); ok {
			if applyRuntimeStatsJSON(statsBody, &snap) {
				populated = true
			}
		}
	}

	if !populated {
		return nil
	}
	return &snap
}
