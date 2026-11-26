package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/config"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/dast"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/graph"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/load"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/manifest"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/pentest"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/policy"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/report"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/runner"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/sast"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/supplychain"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func detectRepoLanguage(targetDir string) types.BoilerplateLanguage {
	if _, err := os.Stat(filepath.Join(targetDir, "mix.exs")); err == nil {
		return types.LangElixir
	}
	if _, err := os.Stat(filepath.Join(targetDir, "go.mod")); err == nil {
		return types.LangGo
	}
	if _, err := os.Stat(filepath.Join(targetDir, "pyproject.toml")); err == nil {
		return types.LangPython
	}
	if _, err := os.Stat(filepath.Join(targetDir, "requirements.txt")); err == nil {
		return types.LangPython
	}
	if _, err := os.Stat(filepath.Join(targetDir, "tsconfig.json")); err == nil {
		return types.LangTypeScript
	}
	if _, err := os.Stat(filepath.Join(targetDir, "package.json")); err == nil {
		return types.LangTypeScript
	}
	return types.LangTypeScript
}

func parseStages(raw string) []string {
	stages := strings.Split(raw, ",")
	for i := range stages {
		stages[i] = strings.TrimSpace(strings.ToLower(stages[i]))
	}
	return stages
}

func stageEnabled(stages []string, target string) bool {
	return slices.Contains(stages, target) || slices.Contains(stages, "all")
}

func buildDASTOptions(baseURL string, m types.BoilerplateManifest, bearerToken string, stages []string, execMode runner.ExecutionMode) dast.DASTOptions {
	return dast.DASTOptions{
		BaseURL:        baseURL,
		OpenAPIURL:     m.OpenAPIURL,
		BearerToken:    bearerToken,
		RequireOpenAPI: stageEnabled(stages, "dast"),
		Mode:           execMode,
	}
}

func resolvePhaseDurations(profile load.LoadProfile, warmupSet, cooldownSet bool, warmupVal, cooldownVal time.Duration) (time.Duration, time.Duration) {
	warmup := warmupVal
	cooldown := cooldownVal
	if !warmupSet {
		if profile == load.ProfileSoak {
			warmup = 20 * time.Second
		} else {
			warmup = 5 * time.Second
		}
	}
	if !cooldownSet {
		if profile == load.ProfileSoak {
			cooldown = 30 * time.Second
		} else {
			cooldown = 5 * time.Second
		}
	}
	return warmup, cooldown
}

func resolveEndpointURL(baseURL, raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return trimmed
	}
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		return trimmed
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return base + trimmed
}

func resolveDiagnosticsCapability(baseURL string, diag *types.DiagnosticsCapability) *types.DiagnosticsCapability {
	if diag == nil || !diag.Enabled {
		return nil
	}
	cp := *diag
	cp.PprofBaseURL = resolveEndpointURL(baseURL, diag.PprofBaseURL)
	cp.RuntimeStatsURL = resolveEndpointURL(baseURL, diag.RuntimeStatsURL)
	cp.GCTriggerURL = resolveEndpointURL(baseURL, diag.GCTriggerURL)
	return &cp
}

func shouldMonitorEgress(stages []string, pid int, container string) bool {
	if pid <= 0 && strings.TrimSpace(container) == "" {
		return false
	}
	return stageEnabled(stages, "dast") || stageEnabled(stages, "pentest") || stageEnabled(stages, "load")
}

func collectAllowedEgressHosts(baseURL string, cfg config.ConformanceConfig) []string {
	var hosts []string
	for _, raw := range []string{baseURL, cfg.PostgresURL, cfg.RedisURL, cfg.MongoURI} {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if h := strings.TrimSpace(u.Hostname()); h != "" && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

func shouldIncludeGraphSourceFile(relPath string, lang types.BoilerplateLanguage) bool {
	lower := strings.ToLower(relPath)
	ext := strings.ToLower(filepath.Ext(relPath))
	switch lang {
	case types.LangTypeScript, types.LangJavaScript:
		for _, suffix := range []string{
			".d.ts", ".spec.ts", ".test.ts", ".test-d.ts",
			".spec.tsx", ".test.tsx", ".spec.js", ".test.js",
			".spec.mjs", ".test.mjs",
		} {
			if strings.HasSuffix(lower, suffix) {
				return false
			}
		}
		return ext == ".ts" || ext == ".tsx" || ext == ".js" || ext == ".mjs" || ext == ".cjs"
	case types.LangGo:
		return ext == ".go" && !strings.HasSuffix(lower, "_test.go")
	case types.LangPython:
		return ext == ".py"
	case types.LangElixir:
		return ext == ".ex" || ext == ".exs"
	default:
		return false
	}
}

func collectSourceFiles(targetDir string, lang types.BoilerplateLanguage) map[string]string {
	files := make(map[string]string)
	skipDirs := map[string]bool{
		".git": true, "node_modules": true, "dist": true, "build": true,
		"vendor": true, "_build": true, "deps": true, ".venv": true, "venv": true, "__pycache__": true,
		"coverage": true, "reports": true, "test": true, "tests": true, "__tests__": true,
		"evals": true, "jest": true, "scripts": true,
	}

	_ = filepath.WalkDir(targetDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != targetDir && ((d.Name() != "." && strings.HasPrefix(d.Name(), ".")) || skipDirs[d.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(targetDir, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !shouldIncludeGraphSourceFile(rel, lang) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		files[rel] = string(b)
		return nil
	})
	return files
}

func loadOpenAPIDoc(ctx context.Context, targetDir, baseURL, openAPIURL string) []byte {
	trimmed := strings.TrimSpace(openAPIURL)
	if trimmed != "" && !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		cand := filepath.Join(targetDir, strings.TrimPrefix(trimmed, "/"))
		if data, err := os.ReadFile(cand); err == nil && len(data) > 0 {
			return data
		}
	}
	for _, rel := range []string{"openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "docs/openapi.json"} {
		if data, err := os.ReadFile(filepath.Join(targetDir, rel)); err == nil && len(data) > 0 {
			return data
		}
	}

	remote := resolveEndpointURL(baseURL, trimmed)
	if !strings.HasPrefix(remote, "http://") && !strings.HasPrefix(remote, "https://") {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, remote, nil)
	if err != nil {
		return nil
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil
	}
	return data
}

func runGraphAndArchitectureStage(
	ctx context.Context,
	targetDir string,
	m types.BoilerplateManifest,
	baseURL string,
	stages []string,
	execMode runner.ExecutionMode,
	onlineEnrich bool,
	card *types.ConformanceScorecard,
	stageErrors *[]string,
) {
	if stageEnabled(stages, "leak-sast") && !stageEnabled(stages, "sast") {
		leakFindings, err := sast.ScanStaticResourceLeaks(targetDir, m.Language)
		if err != nil {
			*stageErrors = append(*stageErrors, fmt.Sprintf("Static leak-sast stage execution error: %v", err))
		}
		card.Findings = append(card.Findings, leakFindings...)
	}

	if !stageEnabled(stages, "graph") && !stageEnabled(stages, "source-graph") {
		return
	}

	srcG, err := graph.BuildSourceGraphFromDir(targetDir, m.Language)
	if err != nil {
		*stageErrors = append(*stageErrors, fmt.Sprintf("Source graph build error: %v", err))
	}
	var sbomG types.DependencyGraph
	if stageEnabled(stages, "graph") {
		var scaFindings []types.SecurityFinding
		var sbomErr error
		sbomG, scaFindings, sbomErr = graph.RunSBOMAndOSVScan(ctx, targetDir, execMode, nil)
		if sbomErr != nil {
			*stageErrors = append(*stageErrors, fmt.Sprintf("SBOM/OSV graph stage error: %v", sbomErr))
		} else {
			card.Findings = append(card.Findings, scaFindings...)
		}
	}

	analyzedSrc, analyzedPkg := graph.AnalyzeDependencyGraphs(srcG, sbomG, card.Findings)
	linkedSrc, linkedPkg, linkedFindings := graph.LinkSourceToPackageReachability(analyzedSrc, analyzedPkg, card.Findings)
	card.Findings = graph.EnrichFindingsWithEPSS(ctx, linkedFindings, onlineEnrich)

	openAPIDoc := loadOpenAPIDoc(ctx, targetDir, baseURL, m.OpenAPIURL)
	if m.Architecture != nil || len(openAPIDoc) > 0 {
		files := collectSourceFiles(targetDir, m.Language)
		archSrc, archFindings := graph.AnalyzeArchitectureAndRouteFlows(targetDir, files, linkedSrc, m.Architecture, openAPIDoc)
		linkedSrc = archSrc
		card.Findings = append(card.Findings, archFindings...)
	}

	card.SourceGraph = linkedSrc
	card.PackageGraph = linkedPkg
}

func runLoadAndMemoryStage(
	ctx context.Context,
	m types.BoilerplateManifest,
	baseURL string,
	profile load.LoadProfile,
	execMode runner.ExecutionMode,
	pid int,
	container string,
	warmup time.Duration,
	cooldown time.Duration,
	pol types.SecurityPolicy,
	card *types.ConformanceScorecard,
	stageErrors *[]string,
) {
	sampling := pid > 0 || strings.TrimSpace(container) != ""
	diag := resolveDiagnosticsCapability(baseURL, m.Capabilities.Diagnostics)

	var preDiag *types.RuntimeTelemetrySnapshot
	var memCancel context.CancelFunc
	var sampleCh <-chan []types.MemorySample

	if sampling {
		preDiag = load.PollDiagnosticsSnapshot(ctx, diag)
		var memCtx context.Context
		memCtx, memCancel = context.WithCancel(ctx)
		defer memCancel()
		sampleCh = load.StartMemorySampler(memCtx, pid, container, time.Second)
	}

	summary, err := load.RunK6LoadTest(ctx, m, baseURL, profile, execMode, nil)

	if sampling {
		if err == nil && cooldown > 0 {
			load.TriggerDiagnosticsGC(ctx, diag)
			timer := time.NewTimer(cooldown)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
		memCancel()
		samples := <-sampleCh
		postDiag := load.PollDiagnosticsSnapshot(ctx, diag)

		var totalReqs int64
		if summary != nil {
			totalReqs = summary.TotalRequests
		}
		if len(samples) > 0 || preDiag != nil || postDiag != nil {
			analysis := load.AnalyzeMemoryPhases(samples, preDiag, postDiag, load.MemoryAnalyzeOptions{
				WarmupDuration:          warmup,
				CooldownDuration:        cooldown,
				TotalRequests:           totalReqs,
				MaxRetainedDriftPercent: pol.MaxRetainedMemoryDriftPercent,
				MaxSlopeBytesPerReq:     pol.MaxMemorySlopeBytesPerReq,
				MaxFDGrowth:             pol.MaxFDGrowth,
				MaxGoroutineGrowth:      pol.MaxGoroutineGrowth,
			})
			card.MemoryAnalysis = &analysis
		}
	}

	if err != nil {
		*stageErrors = append(*stageErrors, fmt.Sprintf("Load-Test stage execution error: %v", err))
		card.LoadTest = &types.LoadTestSummary{
			Profile: string(profile),
			Passed:  false,
		}
		return
	}
	card.LoadTest = summary
}

func main() {
	cfg := config.LoadConfig(os.Getenv)

	defaultPID, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("CONFORMANCE_TARGET_PID")))
	targetFlag := flag.String("target", "", "Path to target boilerplate source repository")
	urlFlag := flag.String("url", cfg.BaseURL, "Running boilerplate Base URL")
	manifestFlag := flag.String("manifest", "", "Path to boilerplate.manifest.json")
	stagesFlag := flag.String("stages", "supplychain,sast,graph,dast,pentest,load", "Comma-separated stages to execute (supplychain,sast,leak-sast,graph,source-graph,dast,pentest,load,all)")
	profileFlag := flag.String("profile", string(load.ProfileBaseline), "k6 load profile (baseline|stress|soak)")
	outputFlag := flag.String("output", "reports", "Output directory for report bundle")
	modeFlag := flag.String("mode", string(runner.ModeAuto), "Tool execution mode (auto|docker|local)")
	imageFlag := flag.String("image", "", "Optional container image reference to scan with Trivy")
	policyFlag := flag.String("policy", "", "Optional path to custom security policy JSON file")
	waiversFlag := flag.String("waivers", "", "Optional path to expiring security waivers JSON file")
	containerFlag := flag.String("container", os.Getenv("CONFORMANCE_TARGET_CONTAINER"), "Optional Docker container name/ID to sample for memory leak detection")
	pidFlag := flag.Int("pid", defaultPID, "Optional host process PID to sample for memory leak detection")
	onlineEnrichFlag := flag.Bool("online-enrich", false, "Enable online package age and EPSS CVE enrichment")
	warmupFlag := flag.Duration("warmup", 0, "Memory soak warmup window (default 5s on baseline/stress, 20s on soak)")
	cooldownFlag := flag.Duration("cooldown", 0, "Memory soak cooldown window (default 5s on baseline/stress, 30s on soak)")
	flag.Parse()

	var warmupSet, cooldownSet bool
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "warmup":
			warmupSet = true
		case "cooldown":
			cooldownSet = true
		}
	})
	loadProfile := load.LoadProfile(*profileFlag)
	warmupDur, cooldownDur := resolvePhaseDurations(loadProfile, warmupSet, cooldownSet, *warmupFlag, *cooldownFlag)

	targetDir := strings.TrimSpace(*targetFlag)
	if targetDir != "" {
		absTarget, err := filepath.Abs(targetDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --target path %q: %v\n", targetDir, err)
			os.Exit(2)
		}
		if info, sErr := os.Stat(absTarget); sErr != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "Target directory %q does not exist or is not a directory\n", absTarget)
			os.Exit(2)
		}
		targetDir = absTarget
	}

	stages := parseStages(*stagesFlag)
	hasStage := func(s string) bool {
		return stageEnabled(stages, s)
	}

	var m types.BoilerplateManifest
	if *manifestFlag != "" {
		loaded, err := manifest.LoadManifest(*manifestFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading manifest %s: %v\n", *manifestFlag, err)
			os.Exit(2)
		}
		m = loaded
	} else if targetDir != "" {
		candidate := filepath.Join(targetDir, "boilerplate.manifest.json")
		loaded, err := manifest.LoadManifest(candidate)
		if err == nil {
			m = loaded
		} else if errors.Is(err, os.ErrNotExist) {
			m = types.BoilerplateManifest{
				Name:     filepath.Base(targetDir),
				Language: detectRepoLanguage(targetDir),
				Capabilities: types.ManifestCapabilities{
					Health: types.EndpointSpec{Method: "GET", Path: "/health"},
				},
			}
		} else {
			fmt.Fprintf(os.Stderr, "Error loading manifest %s: %v\n", candidate, err)
			os.Exit(2)
		}
	} else {
		m = types.BoilerplateManifest{
			Name:     "target-boilerplate",
			Language: types.LangGo,
			Capabilities: types.ManifestCapabilities{
				Health: types.EndpointSpec{Method: "GET", Path: "/health"},
			},
		}
	}

	ctx := context.Background()
	execMode := runner.ExecutionMode(*modeFlag)

	pol := policy.StrictSecurityPolicy()
	if strings.TrimSpace(*policyFlag) != "" {
		loadedPol, err := policy.LoadPolicyFile(*policyFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading policy %s: %v\n", *policyFlag, err)
			os.Exit(2)
		}
		pol = loadedPol
	}

	var waiverFile types.WaiverFile
	hasWaivers := false
	if strings.TrimSpace(*waiversFlag) != "" {
		loadedWaivers, err := policy.LoadWaiverFile(*waiversFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading waivers %s: %v\n", *waiversFlag, err)
			os.Exit(2)
		}
		waiverFile = loadedWaivers
		hasWaivers = true
	} else if targetDir != "" {
		defaultWaivers := filepath.Join(targetDir, ".conformance-waivers.json")
		if _, err := os.Stat(defaultWaivers); err == nil {
			loadedWaivers, wErr := policy.LoadWaiverFile(defaultWaivers)
			if wErr != nil {
				fmt.Fprintf(os.Stderr, "Error loading waivers %s: %v\n", defaultWaivers, wErr)
				os.Exit(2)
			}
			waiverFile = loadedWaivers
			hasWaivers = true
		}
	}

	card := types.ConformanceScorecard{
		TargetName: m.Name,
		Language:   m.Language,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	var stageErrors []string

	if targetDir != "" && hasStage("supplychain") {
		scFindings, err := supplychain.ScanRepositoryWithOptions(ctx, targetDir, m.Language, supplychain.ScanOptions{
			OnlineEnrich: *onlineEnrichFlag,
		})
		if err != nil {
			stageErrors = append(stageErrors, fmt.Sprintf("Supply-chain stage execution error: %v", err))
		}
		card.Findings = append(card.Findings, scFindings...)
	}

	if targetDir != "" && hasStage("sast") {
		findings, err := sast.RunSASTSuiteWithOptions(ctx, targetDir, m.Language, execMode, nil)
		if err != nil {
			stageErrors = append(stageErrors, fmt.Sprintf("SAST stage execution error: %v", err))
		}
		card.Findings = append(card.Findings, findings...)
	}

	if strings.TrimSpace(*imageFlag) != "" && hasStage("sast") {
		imgFindings, err := sast.RunTrivyImageScan(ctx, *imageFlag, execMode, nil)
		if err != nil {
			stageErrors = append(stageErrors, fmt.Sprintf("Container image scan error: %v", err))
		}
		card.Findings = append(card.Findings, imgFindings...)
	}

	if targetDir != "" {
		runGraphAndArchitectureStage(ctx, targetDir, m, *urlFlag, stages, execMode, *onlineEnrichFlag, &card, &stageErrors)
	}

	var egressCancel context.CancelFunc
	var egressCh <-chan []types.EgressViolation
	if *urlFlag != "" && shouldMonitorEgress(stages, *pidFlag, *containerFlag) {
		var egressCtx context.Context
		egressCtx, egressCancel = context.WithCancel(ctx)
		egressCh = pentest.MonitorRuntimeEgress(egressCtx, pentest.EgressMonitorOptions{
			PID:           *pidFlag,
			ContainerName: strings.TrimSpace(*containerFlag),
			AllowedHosts:  collectAllowedEgressHosts(*urlFlag, cfg),
		})
	}

	if *urlFlag != "" && hasStage("dast") {
		var bearerToken string
		if m.Capabilities.Auth != nil {
			tok, tokErr := pentest.AcquireBearerToken(*urlFlag, m)
			if tokErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not acquire DAST bearer token: %v\n", tokErr)
			} else {
				bearerToken = tok
			}
		}
		dFindings, err := dast.RunDASTSuiteWithOptions(ctx, buildDASTOptions(*urlFlag, m, bearerToken, stages, execMode), nil)
		if err != nil {
			stageErrors = append(stageErrors, fmt.Sprintf("DAST stage execution error: %v", err))
		}
		card.Findings = append(card.Findings, dFindings...)
	}

	if *urlFlag != "" && hasStage("pentest") {
		ptResults, err := pentest.RunAutomatedPenTestSuite(ctx, *urlFlag, m, cfg.MockUpstreamPort)
		if err != nil {
			stageErrors = append(stageErrors, fmt.Sprintf("Pen-Test stage execution error: %v", err))
		}
		card.PenTestResults = ptResults
	}

	if *urlFlag != "" && hasStage("load") {
		runLoadAndMemoryStage(ctx, m, *urlFlag, loadProfile, execMode, *pidFlag, strings.TrimSpace(*containerFlag), warmupDur, cooldownDur, pol, &card, &stageErrors)
	}

	if egressCancel != nil {
		egressCancel()
		violations := <-egressCh
		card.EgressViolations = violations
		card.Findings = append(card.Findings, pentest.EgressViolationsToFindings(violations)...)
	}

	var waiverErrs []string
	if hasWaivers {
		card, waiverErrs = policy.ApplySecurityWaivers(card, waiverFile, time.Now().UTC())
	}

	polRes := policy.EvaluateSecurityPolicy(card, pol)
	if len(waiverErrs) > 0 {
		polRes.Passed = false
		polRes.Violations = append(polRes.Violations, waiverErrs...)
	}
	if len(stageErrors) > 0 {
		polRes.Passed = false
		polRes.Violations = append(polRes.Violations, stageErrors...)
	}

	targetOutDir := filepath.Join(*outputFlag, card.TargetName)
	paths, err := report.WriteReportBundle(targetOutDir, card, polRes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing report bundle: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("Report bundle generated for %s:\n", card.TargetName)
	fmt.Printf("  Scorecard: %s\n", paths.ScorecardPath)
	fmt.Printf("  Checksum:  %s\n", paths.ChecksumPath)
	fmt.Printf("  SARIF 2.1: %s\n", paths.SARIFPath)
	fmt.Printf("  Mermaid:   %s\n", paths.MermaidPath)
	fmt.Printf("  Dashboard: %s\n", paths.HTMLPath)

	if !polRes.Passed {
		fmt.Fprintf(os.Stderr, "Policy evaluation FAILED (%d violations):\n", len(polRes.Violations))
		for _, v := range polRes.Violations {
			fmt.Fprintf(os.Stderr, "  - %s\n", v)
		}
		os.Exit(1)
	}
}
