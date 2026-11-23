package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

	targetFlag := flag.String("target", "", "Path to target boilerplate source repository")
	urlFlag := flag.String("url", cfg.BaseURL, "Running boilerplate Base URL")
	manifestFlag := flag.String("manifest", "", "Path to boilerplate.manifest.json")
	stagesFlag := flag.String("stages", "sast,graph,dast,pentest,load", "Comma-separated stages to execute")
	profileFlag := flag.String("profile", string(load.ProfileBaseline), "k6 load profile (baseline|stress|soak)")
	outputFlag := flag.String("output", "reports", "Output directory for 4-part report bundle")
	modeFlag := flag.String("mode", string(runner.ModeAuto), "Tool execution mode (auto|docker|local)")
	flag.Parse()

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
	} else if *targetFlag != "" {
		candidate := filepath.Join(*targetFlag, "boilerplate.manifest.json")
		if loaded, err := manifest.LoadManifest(candidate); err == nil {
			m = loaded
		} else {
			m = types.BoilerplateManifest{
				Name:     filepath.Base(*targetFlag),
				Language: detectRepoLanguage(*targetFlag),
				Capabilities: types.ManifestCapabilities{
					Health: types.EndpointSpec{Method: "GET", Path: "/health"},
				},
			}
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

	card := types.ConformanceScorecard{
		TargetName: m.Name,
		Language:   m.Language,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	if *targetFlag != "" && hasStage("sast") {
		if findings, err := sast.RunSASTSuite(ctx, *targetFlag, execMode, nil); err == nil {
			card.Findings = append(card.Findings, findings...)
		}
	}

	if *targetFlag != "" && hasStage("graph") {
		srcG, err := graph.BuildSourceGraphFromDir(*targetFlag, m.Language)
		if err == nil {
			analyzedSrc, analyzedPkg := graph.AnalyzeDependencyGraphs(srcG, card.PackageGraph, card.Findings)
			card.SourceGraph = analyzedSrc
			card.PackageGraph = analyzedPkg
		}
	}

	if *urlFlag != "" && hasStage("dast") {
		if dFindings, err := dast.RunDASTSuite(ctx, *urlFlag, m.OpenAPIURL, execMode, nil); err == nil {
			card.Findings = append(card.Findings, dFindings...)
		}
	}

	if *urlFlag != "" && hasStage("pentest") {
		if ptResults, err := pentest.RunAutomatedPenTestSuite(ctx, *urlFlag, m, cfg.MockUpstreamPort); err == nil {
			card.PenTestResults = ptResults
		}
	}

	if *urlFlag != "" && hasStage("load") {
		if summary, err := load.RunK6LoadTest(ctx, m, *urlFlag, load.LoadProfile(*profileFlag), execMode, nil); err == nil {
			card.LoadTest = summary
		}
	}

	polRes := policy.EvaluateSecurityPolicy(card, policy.StrictSecurityPolicy())
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
