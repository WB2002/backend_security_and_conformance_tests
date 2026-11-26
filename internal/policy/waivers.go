package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func LoadPolicyFile(filePath string) (types.SecurityPolicy, error) {
	pol := StrictSecurityPolicy()
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return pol, fmt.Errorf("read policy file %s: %w", filePath, err)
	}
	if err := json.Unmarshal(raw, &pol); err != nil {
		return pol, fmt.Errorf("parse policy file %s: %w", filePath, err)
	}
	// Malware findings and unexpected runtime egress are strictly non-waivable and never permitted by policy.
	pol.MaxMalwareFindings = 0
	pol.MaxEgressViolations = 0
	return pol, nil
}

func LoadWaiverFile(filePath string) (types.WaiverFile, error) {
	var wf types.WaiverFile
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return wf, fmt.Errorf("read waiver file %s: %w", filePath, err)
	}
	if err := json.Unmarshal(raw, &wf); err != nil {
		return wf, fmt.Errorf("parse waiver file %s: %w", filePath, err)
	}
	return wf, nil
}

func waiverMatchesFinding(w types.SecurityWaiver, f types.SecurityFinding) bool {
	findingID := strings.TrimSpace(w.FindingID)
	if findingID != "" && findingID == f.ID {
		return true
	}
	ruleOrCVE := strings.TrimSpace(w.RuleOrCVE)
	if ruleOrCVE != "" && (ruleOrCVE == f.CVE || ruleOrCVE == f.ID) {
		return true
	}
	return false
}

func ApplySecurityWaivers(card types.ConformanceScorecard, wf types.WaiverFile, now time.Time) (types.ConformanceScorecard, []string) {
	var violations []string
	var activeWaivers []types.SecurityWaiver

	for idx, w := range wf.Waivers {
		label := strings.TrimSpace(w.FindingID)
		if label == "" {
			label = strings.TrimSpace(w.RuleOrCVE)
		}
		if label == "" {
			label = fmt.Sprintf("#%d", idx+1)
		}

		if strings.TrimSpace(w.FindingID) == "" && strings.TrimSpace(w.RuleOrCVE) == "" {
			violations = append(violations, fmt.Sprintf("invalid waiver %s: missing findingId or ruleOrCve", label))
			continue
		}
		if strings.TrimSpace(w.Justification) == "" {
			violations = append(violations, fmt.Sprintf("invalid waiver %q: missing justification", label))
			continue
		}
		if strings.TrimSpace(w.ApprovedBy) == "" {
			violations = append(violations, fmt.Sprintf("invalid waiver %q: missing approvedBy", label))
			continue
		}
		expRaw := strings.TrimSpace(w.ExpiresAt)
		expTime, err := time.Parse(time.RFC3339, expRaw)
		if err != nil {
			violations = append(violations, fmt.Sprintf("invalid waiver %q: expiresAt %q must be valid RFC3339", label, w.ExpiresAt))
			continue
		}
		if !expTime.After(now) {
			violations = append(violations, fmt.Sprintf("expired waiver %q (expired at %s)", label, expRaw))
			continue
		}
		activeWaivers = append(activeWaivers, w)
	}

	filtered := card
	filtered.Findings = make([]types.SecurityFinding, 0, len(card.Findings))

	for _, f := range card.Findings {
		matched := false
		for _, w := range activeWaivers {
			if waiverMatchesFinding(w, f) {
				matched = true
				break
			}
		}
		if matched {
			if f.Category == types.CategoryMalware {
				violations = append(violations, fmt.Sprintf("cannot waive malware finding %s", f.ID))
				filtered.Findings = append(filtered.Findings, f)
				continue
			}
			// Valid active waiver for non-malware finding: suppress it.
			continue
		}
		filtered.Findings = append(filtered.Findings, f)
	}

	return filtered, violations
}
