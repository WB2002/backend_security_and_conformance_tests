package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
	return types.LangTypeScript
}

func main() {
	cfg := config.LoadConfig(os.Getenv)

	defaultPID, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("CONFORMANCE_TARGET_PID")))
	targetFlag := flag.String("target", "", "Path to target boilerplate source repository")
	urlFlag := flag.String("url", cfg.BaseURL, "Running boilerplate Base URL")
	manifestFlag := flag.String("manifest", "", "Path to boilerplate.manifest.json")
	stagesFlag := flag.String("stages", "sast,graph,dast,pentest,load", "Comma-separated stages to execute")
	profileFlag := flag.String("profile", string(load.ProfileBaseline), "k6 load profile (baseline|stress|soak)")
	outputFlag := flag.String("output", "reports", "Output directory for 4-part report bundle")
	modeFlag := flag.String("mode", string(runner.ModeAuto), "Tool execution mode (auto|docker|local)")
	containerFlag := flag.String("container", os.Getenv("CONFORMANCE_TARGET_CONTAINER"), "Optional Docker container name/ID to sample for memory leak detection")
	pidFlag := flag.Int("pid", defaultPID, "Optional host process PID to sample for memory leak detection")
	flag.Parse()

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

	stages := strings.Split(*stagesFlag, ",")
	for i := range stages {
		stages[i] = strings.TrimSpace(strings.ToLower(stages[i]))
	}
	hasStage := func(s string) bool {
		return slices.Contains(stages, s) || slices.Contains(stages, "all")
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

	card := types.ConformanceScorecard{
		TargetName: m.Name,
		Language:   m.Language,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	var stageErrors []string

	if targetDir != "" && hasStage("sast") {
		findings, err := sast.RunSASTSuite(ctx, targetDir, execMode, nil)
		if err != nil {
			stageErrors = append(stageErrors, fmt.Sprintf("SAST stage execution error: %v", err))
		}
		card.Findings = append(card.Findings, findings...)
	}

	if targetDir != "" && hasStage("graph") {
		srcG, err := graph.BuildSourceGraphFromDir(targetDir, m.Language)
		if err != nil {
			stageErrors = append(stageErrors, fmt.Sprintf("Source graph build error: %v", err))
		}
		sbomG, scaFindings, sbomErr := graph.RunSBOMAndOSVScan(ctx, targetDir, execMode, nil)
		if sbomErr != nil {
			stageErrors = append(stageErrors, fmt.Sprintf("SBOM/OSV graph stage error: %v", sbomErr))
		} else {
			card.Findings = append(card.Findings, scaFindings...)
		}
		analyzedSrc, analyzedPkg := graph.AnalyzeDependencyGraphs(srcG, sbomG, card.Findings)
		card.SourceGraph = analyzedSrc
		card.PackageGraph = analyzedPkg
	}

	if *urlFlag != "" && hasStage("dast") {
		dFindings, err := dast.RunDASTSuite(ctx, *urlFlag, m.OpenAPIURL, execMode, nil)
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
		memCtx, cancelMem := context.WithCancel(ctx)
		memCh := make(chan *types.MemoryLeakAnalysis, 1)
		go func() {
			if *pidFlag > 0 {
				memCh <- load.SampleProcessMemory(memCtx, *pidFlag, 2*time.Second, pol.MaxMemoryDriftPercent)
			} else if strings.TrimSpace(*containerFlag) != "" {
				memCh <- load.SampleDockerContainerMemory(memCtx, *containerFlag, 2*time.Second, pol.MaxMemoryDriftPercent)
			} else {
				memCh <- nil
			}
		}()

		summary, err := load.RunK6LoadTest(ctx, m, *urlFlag, load.LoadProfile(*profileFlag), execMode, nil)
		cancelMem()
		card.MemoryAnalysis = <-memCh

		if err != nil {
			stageErrors = append(stageErrors, fmt.Sprintf("Load-Test stage execution error: %v", err))
			card.LoadTest = &types.LoadTestSummary{
				Profile: string(*profileFlag),
				Passed:  false,
			}
		} else {
			card.LoadTest = summary
		}
	}

	polRes := policy.EvaluateSecurityPolicy(card, pol)
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
