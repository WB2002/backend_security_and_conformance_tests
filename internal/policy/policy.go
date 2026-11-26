package policy

import (
	"fmt"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func StrictSecurityPolicy() types.SecurityPolicy {
	return types.SecurityPolicy{
		FailOnAnySourceCycle:          true,
		FailOnAnyPackageCycle:         true,
		FailOnLayerViolation:          true,
		FailOnUnprotectedRoute:        true,
		FailOnShadowRoute:             true,
		MaxCriticalFindings:           0,
		MaxHighFindings:               0,
		MaxMalwareFindings:            0,
		MaxPenTestFailures:            0,
		RequireLoadTestPass:           true,
		RequireMemoryOnSoak:           true,
		MaxMemoryDriftPercent:         20.0,
		MaxRetainedMemoryDriftPercent: 15.0,
		MaxMemorySlopeBytesPerReq:     1024.0,
		MaxFDGrowth:                   32,
		MaxGoroutineGrowth:            32,
		MaxEgressViolations:           0,
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

	if policy.FailOnLayerViolation && len(scorecard.SourceGraph.LayerViolations) > 0 {
		violations = append(violations, fmt.Sprintf("detected %d architecture layer boundary violation(s)", len(scorecard.SourceGraph.LayerViolations)))
	}

	var unprotectedRoutes, shadowRoutes int
	for _, rf := range scorecard.SourceGraph.RouteFindings {
		switch rf.Kind {
		case "unprotected-route":
			unprotectedRoutes++
		case "shadow-route":
			shadowRoutes++
		}
	}
	if policy.FailOnUnprotectedRoute && unprotectedRoutes > 0 {
		violations = append(violations, fmt.Sprintf("detected %d unprotected route(s) missing required guards", unprotectedRoutes))
	}
	if policy.FailOnShadowRoute && shadowRoutes > 0 {
		violations = append(violations, fmt.Sprintf("detected %d undocumented shadow route(s)", shadowRoutes))
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

	if ma := scorecard.MemoryAnalysis; ma != nil {
		if policy.MaxRetainedMemoryDriftPercent > 0 && ma.RetainedDriftPercent > policy.MaxRetainedMemoryDriftPercent {
			violations = append(violations, fmt.Sprintf("retained memory drift %.2f%% exceeds maximum allowed %.2f%%", ma.RetainedDriftPercent, policy.MaxRetainedMemoryDriftPercent))
		} else if ma.PostWarmupBaselineBytes == 0 && ma.LeakDetected && policy.MaxMemoryDriftPercent > 0 && ma.DriftPercent > policy.MaxMemoryDriftPercent {
			violations = append(violations, fmt.Sprintf("memory leak detected (drift %.2f%% exceeds %.2f%%)", ma.DriftPercent, policy.MaxMemoryDriftPercent))
		}
		if policy.MaxMemorySlopeBytesPerReq > 0 && ma.SlopeBytesPerReq > policy.MaxMemorySlopeBytesPerReq {
			violations = append(violations, fmt.Sprintf("memory slope %.2f bytes/req exceeds maximum allowed %.2f bytes/req", ma.SlopeBytesPerReq, policy.MaxMemorySlopeBytesPerReq))
		}
		if policy.MaxFDGrowth > 0 && ma.FDDelta > policy.MaxFDGrowth {
			violations = append(violations, fmt.Sprintf("file descriptor growth (%d) exceeds maximum allowed (%d)", ma.FDDelta, policy.MaxFDGrowth))
		}
		if policy.MaxGoroutineGrowth > 0 && ma.GoroutineDelta > policy.MaxGoroutineGrowth {
			violations = append(violations, fmt.Sprintf("goroutine growth (%d) exceeds maximum allowed (%d)", ma.GoroutineDelta, policy.MaxGoroutineGrowth))
		}
	}

	if len(scorecard.EgressViolations) > policy.MaxEgressViolations {
		violations = append(violations, fmt.Sprintf("unexpected runtime egress connections (%d) exceed maximum allowed (%d)", len(scorecard.EgressViolations), policy.MaxEgressViolations))
	}

	return types.PolicyEvaluationResult{
		Passed:     len(violations) == 0,
		Violations: violations,
	}
}
