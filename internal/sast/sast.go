package sast

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/runner"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func NormalizeRelativePath(rawPath, targetDir string) string {
	p := filepath.ToSlash(strings.TrimSpace(rawPath))
	p = strings.TrimPrefix(p, "/workspace/")
	p = strings.TrimPrefix(p, "/workspace")
	if targetDir != "" {
		td := filepath.ToSlash(strings.TrimRight(targetDir, "/"))
		if strings.HasPrefix(p, td+"/") {
			p = strings.TrimPrefix(p, td+"/")
		} else if abs, err := filepath.Abs(targetDir); err == nil {
			absSlash := filepath.ToSlash(strings.TrimRight(abs, "/"))
			if strings.HasPrefix(p, absSlash+"/") {
				p = strings.TrimPrefix(p, absSlash+"/")
			} else if base := filepath.Base(absSlash); base != "" && base != "." && base != "/" {
				if idx := strings.Index(p, "/"+base+"/"); idx >= 0 {
					p = p[idx+len(base)+2:]
				}
			}
		}
	}
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	return p
}

func mapSeverity(raw string) types.Severity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return types.SeverityCritical
	case "ERROR", "HIGH":
		return types.SeverityHigh
	case "WARNING", "MEDIUM":
		return types.SeverityMedium
	case "INFO", "LOW":
		return types.SeverityLow
	default:
		return types.SeverityMedium
	}
}

func extractFirstCWE(raw any) string {
	switch v := raw.(type) {
	case string:
		return strings.Split(v, ":")[0]
	case []any:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return strings.Split(s, ":")[0]
			}
		}
	case []string:
		if len(v) > 0 {
			return strings.Split(v[0], ":")[0]
		}
	}
	return ""
}

type semgrepResponse struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
			Col  int `json:"col"`
		} `json:"start"`
		Extra struct {
			Severity string         `json:"severity"`
			Message  string         `json:"message"`
			Metadata map[string]any `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

func ParseSemgrepOutput(rawJSON []byte, targetDir string) ([]types.SecurityFinding, error) {
	if len(strings.TrimSpace(string(rawJSON))) == 0 {
		return nil, nil
	}
	var parsed semgrepResponse
	if err := json.Unmarshal(rawJSON, &parsed); err != nil {
		return nil, fmt.Errorf("parse semgrep json: %w", err)
	}
	var findings []types.SecurityFinding
	for i, r := range parsed.Results {
		relPath := NormalizeRelativePath(r.Path, targetDir)
		cwe := extractFirstCWE(r.Extra.Metadata["cwe"])
		findings = append(findings, types.SecurityFinding{
			ID:          fmt.Sprintf("semgrep-%d-%s", i+1, r.CheckID),
			Category:    types.CategorySAST,
			Tool:        "semgrep",
			Severity:    mapSeverity(r.Extra.Severity),
			Title:       r.CheckID,
			Description: r.Extra.Message,
			FilePath:    relPath,
			Line:        r.Start.Line,
			CWE:         cwe,
		})
	}
	return findings, nil
}

type gitleaksItem struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	Fingerprint string `json:"Fingerprint"`
}

func ParseGitleaksOutput(rawJSON []byte, targetDir string) ([]types.SecurityFinding, error) {
	trimmed := strings.TrimSpace(string(rawJSON))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var items []gitleaksItem
	if err := json.Unmarshal(rawJSON, &items); err != nil {
		return nil, fmt.Errorf("parse gitleaks json: %w", err)
	}
	var findings []types.SecurityFinding
	for i, item := range items {
		id := item.Fingerprint
		if id == "" {
			id = fmt.Sprintf("gitleaks-%d-%s", i+1, item.RuleID)
		}
		findings = append(findings, types.SecurityFinding{
			ID:          id,
			Category:    types.CategorySecret,
			Tool:        "gitleaks",
			Severity:    types.SeverityCritical,
			Title:       fmt.Sprintf("Hardcoded secret (%s)", item.RuleID),
			Description: item.Description,
			FilePath:    NormalizeRelativePath(item.File, targetDir),
			Line:        item.StartLine,
			CWE:         "CWE-798",
		})
	}
	return findings, nil
}

type trivyResponse struct {
	Results []struct {
		Target            string `json:"Target"`
		Misconfigurations []struct {
			ID            string `json:"ID"`
			Title         string `json:"Title"`
			Description   string `json:"Description"`
			Severity      string `json:"Severity"`
			CauseMetadata struct {
				StartLine int `json:"StartLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			Description      string `json:"Description"`
		} `json:"Vulnerabilities"`
		Secrets []struct {
			RuleID    string `json:"RuleID"`
			Category  string `json:"Category"`
			Severity  string `json:"Severity"`
			Title     string `json:"Title"`
			Match     string `json:"Match"`
			StartLine int    `json:"StartLine"`
		} `json:"Secrets"`
	} `json:"Results"`
}

func ParseTrivyFSOutput(rawJSON []byte, targetDir string) ([]types.SecurityFinding, error) {
	if len(strings.TrimSpace(string(rawJSON))) == 0 {
		return nil, nil
	}
	var parsed trivyResponse
	if err := json.Unmarshal(rawJSON, &parsed); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}
	var findings []types.SecurityFinding
	for _, res := range parsed.Results {
		relTarget := NormalizeRelativePath(res.Target, targetDir)
		for i, mis := range res.Misconfigurations {
			findings = append(findings, types.SecurityFinding{
				ID:          fmt.Sprintf("trivy-iac-%s-%d", mis.ID, i+1),
				Category:    types.CategoryIaC,
				Tool:        "trivy",
				Severity:    mapSeverity(mis.Severity),
				Title:       mis.Title,
				Description: mis.Description,
				FilePath:    relTarget,
				Line:        mis.CauseMetadata.StartLine,
			})
		}
		for i, vuln := range res.Vulnerabilities {
			findings = append(findings, types.SecurityFinding{
				ID:          fmt.Sprintf("trivy-sca-%s-%s-%d", vuln.VulnerabilityID, vuln.PkgName, i+1),
				Category:    types.CategorySCA,
				Tool:        "trivy",
				Severity:    mapSeverity(vuln.Severity),
				Title:       vuln.Title,
				Description: vuln.Description,
				FilePath:    relTarget,
				CVE:         vuln.VulnerabilityID,
				PackageName: vuln.PkgName,
			})
		}
		for i, sec := range res.Secrets {
			ruleID := strings.TrimSpace(sec.RuleID)
			if ruleID == "" {
				ruleID = "secret"
			}
			title := strings.TrimSpace(sec.Title)
			if title == "" {
				title = fmt.Sprintf("Hardcoded secret (%s)", ruleID)
			}
			desc := fmt.Sprintf("Secret detected (%s)", ruleID)
			if cat := strings.TrimSpace(sec.Category); cat != "" {
				desc = fmt.Sprintf("%s (%s)", cat, ruleID)
			}
			findings = append(findings, types.SecurityFinding{
				ID:          fmt.Sprintf("trivy-secret-%s-%d", ruleID, i+1),
				Category:    types.CategorySecret,
				Tool:        "trivy",
				Severity:    mapSeverity(sec.Severity),
				Title:       title,
				Description: desc,
				FilePath:    relTarget,
				Line:        sec.StartLine,
				CWE:         "CWE-798",
			})
		}
	}
	return findings, nil
}

func RunSASTSuite(ctx context.Context, targetDir string, mode runner.ExecutionMode, execFn runner.CommandExecutor) ([]types.SecurityFinding, error) {
	var all []types.SecurityFinding

	scanPathFor := func(tool runner.ToolName) string {
		if runner.ResolveEffectiveMode(mode, tool) == runner.ModeDocker {
			return "/workspace"
		}
		return targetDir
	}

	semgrepRes, err := runner.RunTool(ctx, runner.ToolInvocationOptions{
		Tool:             runner.ToolSemgrep,
		Args:             []string{"scan", "--config", "auto", "--metrics=off", "--json", "--quiet", "--exclude", "node_modules", "--exclude", "dist", "--exclude", "test/security/semgrep-fixtures", "--exclude", ".conformance-runner", "--exclude", ".worktrees", "--exclude", ".tsd-emit", "--exclude", "coverage", scanPathFor(runner.ToolSemgrep)},
		TargetDir:        targetDir,
		Mode:             mode,
		AllowedExitCodes: []int{0, 1},
	}, execFn)
	if err != nil {
		return nil, fmt.Errorf("semgrep execution failed: %w", err)
	}
	if strings.TrimSpace(semgrepRes.Stdout) != "" {
		f, pErr := ParseSemgrepOutput([]byte(semgrepRes.Stdout), targetDir)
		if pErr != nil {
			return nil, pErr
		}
		all = append(all, f...)
	}

	gitleaksArgs := []string{"detect", "--source", scanPathFor(runner.ToolGitleaks)}
	if _, gitErr := os.Stat(filepath.Join(targetDir, ".git")); gitErr != nil {
		gitleaksArgs = append(gitleaksArgs, "--no-git")
	}
	gitleaksArgs = append(gitleaksArgs, "--report-format", "json", "--report-path", "-")
	if _, statErr := os.Stat(filepath.Join(targetDir, ".gitleaks.toml")); statErr == nil {
		gitleaksArgs = append(gitleaksArgs, "--config", filepath.ToSlash(filepath.Join(scanPathFor(runner.ToolGitleaks), ".gitleaks.toml")))
	}

	gitleaksRes, err := runner.RunTool(ctx, runner.ToolInvocationOptions{
		Tool:             runner.ToolGitleaks,
		Args:             gitleaksArgs,
		TargetDir:        targetDir,
		Mode:             mode,
		AllowedExitCodes: []int{0, 1},
	}, execFn)
	if err != nil {
		return nil, fmt.Errorf("gitleaks execution failed: %w", err)
	}
	if strings.TrimSpace(gitleaksRes.Stdout) != "" {
		f, pErr := ParseGitleaksOutput([]byte(gitleaksRes.Stdout), targetDir)
		if pErr != nil {
			return nil, pErr
		}
		all = append(all, f...)
	}

	trivyRes, err := runner.RunTool(ctx, runner.ToolInvocationOptions{
		Tool:             runner.ToolTrivy,
		Args:             []string{"fs", "--scanners", "vuln,misconfig,secret", "--format", "json", "--quiet", "--skip-dirs", "node_modules,dist,.git,.conformance-runner,.worktrees,.tsd-emit,coverage,test,tests", scanPathFor(runner.ToolTrivy)},
		TargetDir:        targetDir,
		Mode:             mode,
		AllowedExitCodes: []int{0, 1},
	}, execFn)
	if err != nil {
		return nil, fmt.Errorf("trivy execution failed: %w", err)
	}
	if strings.TrimSpace(trivyRes.Stdout) != "" {
		f, pErr := ParseTrivyFSOutput([]byte(trivyRes.Stdout), targetDir)
		if pErr != nil {
			return nil, pErr
		}
		all = append(all, f...)
	}

	return all, nil
}

func RunTrivyImageScan(ctx context.Context, imageRef string, mode runner.ExecutionMode, execFn runner.CommandExecutor) ([]types.SecurityFinding, error) {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return nil, nil
	}
	res, err := runner.RunTool(ctx, runner.ToolInvocationOptions{
		Tool:             runner.ToolTrivy,
		Args:             []string{"image", "--scanners", "vuln,misconfig,secret", "--format", "json", "--quiet", imageRef},
		Mode:             mode,
		AllowedExitCodes: []int{0, 1},
	}, execFn)
	if err != nil {
		return nil, fmt.Errorf("trivy image scan failed: %w", err)
	}
	if strings.TrimSpace(res.Stdout) == "" {
		return nil, nil
	}
	return ParseTrivyFSOutput([]byte(res.Stdout), "")
}
