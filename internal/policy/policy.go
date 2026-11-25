package policy

import (
	"fmt"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func StrictSecurityPolicy() types.SecurityPolicy {
	return types.SecurityPolicy{
		FailOnAnySourceCycle:  true,
		FailOnAnyPackageCycle: true,
		MaxCriticalFindings:   0,
		MaxHighFindings:       0,
		MaxMalwareFindings:    0,
		MaxPenTestFailures:    0,
		RequireLoadTestPass:   true,
		RequireMemoryOnSoak:   true,
		MaxMemoryDriftPercent: 20.0,
	}
}

func EvaluateSecurityPolicy(scorecard types.ConformanceScorecard, policy types.SecurityPolicy) types.PolicyEvaluationResult {
	var violations []string

	if policy.FailOnAnySourceCycle && len(scorecard.SourceGraph.Cycles) > 0 {
		violations = append(violations, fmt.Sprintf("detected %d source module dependency cycle(s)", len(scorecard.SourceGraph.Cycles)))
	}

	if policy.FailOnAnyPackageCycle && len(scorecard.PackageGraph.Cycles) > 0 {
		violations = append(violations, fmt.Sprintf("detected %d package dependency cycle(s)", len(scorecard.PackageGraph.Cycles)))
	}

	var criticalCount, highCount, malwareCount int
	for _, f := range scorecard.Findings {
		if f.Category == types.CategoryMalware {
			malwareCount++
		}
		switch f.Severity {
		case types.SeverityCritical:
			criticalCount++
		case types.SeverityHigh:
			highCount++
		}
	}

	if malwareCount > policy.MaxMalwareFindings {
		violations = append(violations, fmt.Sprintf("malware findings (%d) exceed maximum allowed (%d)", malwareCount, policy.MaxMalwareFindings))
	}
	if criticalCount > policy.MaxCriticalFindings {
		violations = append(violations, fmt.Sprintf("critical findings (%d) exceed maximum allowed (%d)", criticalCount, policy.MaxCriticalFindings))
	}
	if highCount > policy.MaxHighFindings {
		violations = append(violations, fmt.Sprintf("high findings (%d) exceed maximum allowed (%d)", highCount, policy.MaxHighFindings))
	}

	var penTestFailures int
	for _, pt := range scorecard.PenTestResults {
		if pt.Status == "failed" {
			penTestFailures++
		}
	}
	if penTestFailures > policy.MaxPenTestFailures {
		violations = append(violations, fmt.Sprintf("pen-test failures (%d) exceed maximum allowed (%d)", penTestFailures, policy.MaxPenTestFailures))
	}

	if policy.RequireLoadTestPass && scorecard.LoadTest != nil && !scorecard.LoadTest.Passed {
		violations = append(violations, fmt.Sprintf("load test profile %q failed SLA thresholds", scorecard.LoadTest.Profile))
	}

	if policy.RequireMemoryOnSoak && scorecard.LoadTest != nil && scorecard.LoadTest.Profile == "soak" && scorecard.MemoryAnalysis == nil {
		violations = append(violations, "soak load test requires memory telemetry (--container or --pid) for leak analysis")
	}

	if scorecard.MemoryAnalysis != nil {
		if scorecard.MemoryAnalysis.LeakDetected || (policy.MaxMemoryDriftPercent > 0 && scorecard.MemoryAnalysis.DriftPercent > policy.MaxMemoryDriftPercent) {
			violations = append(violations, fmt.Sprintf("memory leak detected (drift %.2f%% exceeds %.2f%%)", scorecard.MemoryAnalysis.DriftPercent, policy.MaxMemoryDriftPercent))
		}
	}

	return types.PolicyEvaluationResult{
		Passed:     len(violations) == 0,
		Violations: violations,
	}
}
