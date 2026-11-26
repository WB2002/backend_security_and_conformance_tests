package sast

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/runner"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func boolPtr(v bool) *bool {
	return &v
}

func parseFirstInt(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	for i, r := range raw {
		if r < '0' || r > '9' {
			raw = raw[:i]
			break
		}
	}
	n, _ := strconv.Atoi(raw)
	return n
}

func formatCWE(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToUpper(id), "CWE-") {
		return strings.ToUpper(id)
	}
	return "CWE-" + id
}

type gosecOutput struct {
	Issues []struct {
		Severity   string `json:"severity"`
		Confidence string `json:"confidence"`
		CWE        struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		} `json:"cwe"`
		RuleID  string `json:"rule_id"`
		Details string `json:"details"`
		File    string `json:"file"`
		Line    string `json:"line"`
		Column  string `json:"column"`
	} `json:"Issues"`
}

func ParseGosecOutput(rawJSON []byte, targetDir string) ([]types.SecurityFinding, error) {
	if len(strings.TrimSpace(string(rawJSON))) == 0 {
		return nil, nil
	}
	var parsed gosecOutput
	if err := json.Unmarshal(rawJSON, &parsed); err != nil {
		return nil, fmt.Errorf("parse gosec json: %w", err)
	}
	findings := make([]types.SecurityFinding, 0, len(parsed.Issues))
	for i, issue := range parsed.Issues {
		findings = append(findings, types.SecurityFinding{
			ID:          fmt.Sprintf("gosec-%d-%s", i+1, issue.RuleID),
			Category:    types.CategorySAST,
			Tool:        "gosec",
			Severity:    mapSeverity(issue.Severity),
			Title:       fmt.Sprintf("%s: %s", issue.RuleID, issue.Details),
			Description: issue.Details,
			FilePath:    NormalizeRelativePath(issue.File, targetDir),
			Line:        parseFirstInt(issue.Line),
			CWE:         formatCWE(issue.CWE.ID),
		})
	}
	return findings, nil
}

type govulncheckMessage struct {
	OSV *struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases"`
		Summary string   `json:"summary"`
		Details string   `json:"details"`
	} `json:"osv,omitempty"`
	Finding *struct {
		OSV          string `json:"osv"`
		FixedVersion string `json:"fixed_version"`
		Trace        []struct {
			Module   string `json:"module"`
			Version  string `json:"version"`
			Package  string `json:"package"`
			Function string `json:"function"`
			Position *struct {
				Filename string `json:"filename"`
				Line     int    `json:"line"`
				Column   int    `json:"column"`
			} `json:"position,omitempty"`
		} `json:"trace"`
	} `json:"finding,omitempty"`
}

func ParseGovulncheckOutput(rawStream []byte, targetDir string) ([]types.SecurityFinding, error) {
	if len(strings.TrimSpace(string(rawStream))) == 0 {
		return nil, nil
	}
	type osvInfo struct {
		ID      string
		CVE     string
		Summary string
		Details string
	}
	osvs := make(map[string]osvInfo)
	var rawFindings []*govulncheckMessage

	dec := json.NewDecoder(bytes.NewReader(rawStream))
	for {
		var msg govulncheckMessage
		if err := dec.Decode(&msg); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parse govulncheck json stream: %w", err)
		}
		if msg.OSV != nil {
			cve := msg.OSV.ID
			for _, alias := range msg.OSV.Aliases {
				if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
					cve = alias
					break
				}
			}
			osvs[msg.OSV.ID] = osvInfo{
				ID:      msg.OSV.ID,
				CVE:     cve,
				Summary: msg.OSV.Summary,
				Details: msg.OSV.Details,
			}
		}
		if msg.Finding != nil {
			copied := msg
			rawFindings = append(rawFindings, &copied)
		}
	}

	findings := make([]types.SecurityFinding, 0, len(rawFindings))
	for i, msg := range rawFindings {
		f := msg.Finding
		info := osvs[f.OSV]
		cve := info.CVE
		if cve == "" {
			cve = f.OSV
		}
		title := info.Summary
		if title == "" {
			title = fmt.Sprintf("Reachable Go vulnerability %s", cve)
		}
		desc := info.Details
		if desc == "" {
			desc = title
		}
		if f.FixedVersion != "" {
			desc = fmt.Sprintf("%s (fixed in %s)", desc, f.FixedVersion)
		}

		var pkgName, firstFile string
		var firstLine int
		var steps []types.CodeFlowStep
		for idx, frame := range f.Trace {
			if pkgName == "" {
				if frame.Package != "" {
					pkgName = frame.Package
				} else if frame.Module != "" {
					pkgName = frame.Module
				}
			}
			file := ""
			line := 0
			col := 0
			if frame.Position != nil {
				file = NormalizeRelativePath(frame.Position.Filename, targetDir)
				line = frame.Position.Line
				col = frame.Position.Column
			}
			if firstFile == "" && file != "" {
				firstFile = file
				firstLine = line
			}
			kind := "propagator"
			if len(f.Trace) == 1 || idx == len(f.Trace)-1 {
				kind = "sink"
			} else if idx == 0 {
				kind = "source"
			}
			label := frame.Function
			if frame.Package != "" && frame.Function != "" {
				label = frame.Package + "." + frame.Function
			} else if frame.Module != "" {
				label = frame.Module
			}
			steps = append(steps, types.CodeFlowStep{
				FilePath: file,
				Line:     line,
				Column:   col,
				Message:  label,
				Kind:     kind,
			})
		}

		secFinding := types.SecurityFinding{
			ID:          fmt.Sprintf("govulncheck-%d-%s", i+1, f.OSV),
			Category:    types.CategorySCA,
			Tool:        "govulncheck",
			Severity:    types.SeverityHigh,
			Title:       title,
			Description: desc,
			FilePath:    firstFile,
			Line:        firstLine,
			CVE:         cve,
			PackageName: pkgName,
			Reachable:   boolPtr(true),
		}
		if len(steps) > 0 {
			secFinding.CodeFlows = [][]types.CodeFlowStep{steps}
		}
		findings = append(findings, secFinding)
	}
	return findings, nil
}

type banditOutput struct {
	Results []struct {
		TestID          string `json:"test_id"`
		TestName        string `json:"test_name"`
		IssueSeverity   string `json:"issue_severity"`
		IssueConfidence string `json:"issue_confidence"`
		IssueText       string `json:"issue_text"`
		Filename        string `json:"filename"`
		LineNumber      int    `json:"line_number"`
		IssueCWE        struct {
			ID   int    `json:"id"`
			Link string `json:"link"`
		} `json:"issue_cwe"`
	} `json:"results"`
}

func ParseBanditOutput(rawJSON []byte, targetDir string) ([]types.SecurityFinding, error) {
	if len(strings.TrimSpace(string(rawJSON))) == 0 {
		return nil, nil
	}
	var parsed banditOutput
	if err := json.Unmarshal(rawJSON, &parsed); err != nil {
		return nil, fmt.Errorf("parse bandit json: %w", err)
	}
	findings := make([]types.SecurityFinding, 0, len(parsed.Results))
	for i, r := range parsed.Results {
		cwe := ""
		if r.IssueCWE.ID > 0 {
			cwe = fmt.Sprintf("CWE-%d", r.IssueCWE.ID)
		}
		title := r.TestID
		if r.TestName != "" {
			title = fmt.Sprintf("%s (%s)", r.TestID, r.TestName)
		}
		findings = append(findings, types.SecurityFinding{
			ID:          fmt.Sprintf("bandit-%d-%s", i+1, r.TestID),
			Category:    types.CategorySAST,
			Tool:        "bandit",
			Severity:    mapSeverity(r.IssueSeverity),
			Title:       title,
			Description: r.IssueText,
			FilePath:    NormalizeRelativePath(r.Filename, targetDir),
			Line:        r.LineNumber,
			CWE:         cwe,
		})
	}
	return findings, nil
}

type sobelowFinding struct {
	Type string `json:"type"`
	File string `json:"file"`
	Line int    `json:"line"`
}

type sobelowOutput struct {
	Findings struct {
		HighConfidence   []sobelowFinding `json:"high_confidence"`
		MediumConfidence []sobelowFinding `json:"medium_confidence"`
		LowConfidence    []sobelowFinding `json:"low_confidence"`
	} `json:"findings"`
}

func inferSobelowCWE(findingType string) string {
	upper := strings.ToUpper(findingType)
	switch {
	case strings.Contains(upper, "SQL"):
		return "CWE-89"
	case strings.Contains(upper, "XSS"):
		return "CWE-79"
	case strings.Contains(upper, "TRAVERSAL"):
		return "CWE-22"
	case strings.Contains(upper, "RCE"), strings.Contains(upper, "CI."):
		return "CWE-78"
	case strings.Contains(upper, "CSRF"):
		return "CWE-352"
	case strings.Contains(upper, "BINTOTERM"), strings.Contains(upper, "DOS.BIN"):
		return "CWE-502"
	case strings.Contains(upper, "HTTPS"):
		return "CWE-319"
	default:
		return ""
	}
}

func ParseSobelowOutput(rawJSON []byte, targetDir string) ([]types.SecurityFinding, error) {
	if len(strings.TrimSpace(string(rawJSON))) == 0 {
		return nil, nil
	}
	var parsed sobelowOutput
	if err := json.Unmarshal(rawJSON, &parsed); err != nil {
		return nil, fmt.Errorf("parse sobelow json: %w", err)
	}
	var findings []types.SecurityFinding
	appendBucket := func(items []sobelowFinding, sev types.Severity, bucket string) {
		for i, item := range items {
			findings = append(findings, types.SecurityFinding{
				ID:          fmt.Sprintf("sobelow-%s-%d", bucket, i+1),
				Category:    types.CategorySAST,
				Tool:        "sobelow",
				Severity:    sev,
				Title:       item.Type,
				Description: item.Type,
				FilePath:    NormalizeRelativePath(item.File, targetDir),
				Line:        item.Line,
				CWE:         inferSobelowCWE(item.Type),
			})
		}
	}
	appendBucket(parsed.Findings.HighConfidence, types.SeverityHigh, "high")
	appendBucket(parsed.Findings.MediumConfidence, types.SeverityMedium, "medium")
	appendBucket(parsed.Findings.LowConfidence, types.SeverityLow, "low")
	return findings, nil
}

func ParseYARAOutput(rawOutput []byte, targetDir string) ([]types.SecurityFinding, error) {
	var findings []types.SecurityFinding
	scanner := bufio.NewScanner(bytes.NewReader(rawOutput))
	idx := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ruleName := fields[0]
		filePath := fields[len(fields)-1]
		idx++
		findings = append(findings, types.SecurityFinding{
			ID:          fmt.Sprintf("yara-%d-%s", idx, ruleName),
			Category:    types.CategoryMalware,
			Tool:        "yara",
			Severity:    types.SeverityCritical,
			Title:       fmt.Sprintf("YARA rule match: %s", ruleName),
			Description: fmt.Sprintf("File matched YARA malware signature %s", ruleName),
			FilePath:    NormalizeRelativePath(filePath, targetDir),
			CWE:         "CWE-506",
		})
	}
	return findings, scanner.Err()
}

var skipHygieneDirs = map[string]bool{
	".git":                true,
	"node_modules":        true,
	"dist":                true,
	"vendor":              true,
	".worktrees":          true,
	".conformance-runner": true,
	".tsd-emit":           true,
	"coverage":            true,
	"_build":              true,
	"deps":                true,
	".venv":               true,
	"venv":                true,
}

func isSensitiveEnvFile(base string) bool {
	lower := strings.ToLower(base)
	if !strings.HasPrefix(lower, ".env") {
		return false
	}
	switch lower {
	case ".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults":
		return false
	}
	if strings.HasSuffix(lower, ".example") || strings.HasSuffix(lower, ".sample") || strings.HasSuffix(lower, ".template") {
		return false
	}
	return lower == ".env" || strings.HasPrefix(lower, ".env.")
}

func ScanGitRepoHygiene(targetDir string) ([]types.SecurityFinding, error) {
	if targetDir == "" {
		return nil, nil
	}
	if _, err := os.Stat(targetDir); err != nil {
		return nil, nil
	}

	var findings []types.SecurityFinding
	if _, err := os.Stat(filepath.Join(targetDir, ".git", "shallow")); err == nil {
		findings = append(findings, types.SecurityFinding{
			ID:          "git-hygiene-shallow-clone",
			Category:    types.CategorySupplyChain,
			Tool:        "git-hygiene",
			Severity:    types.SeverityMedium,
			Title:       "Shallow git clone hides historical secret leaks",
			Description: "Repository contains .git/shallow; full git history is unavailable to gitleaks secret scanning.",
			FilePath:    ".git/shallow",
		})
	}

	envIdx := 0
	err := filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if path != targetDir && skipHygieneDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}
		if isSensitiveEnvFile(name) {
			envIdx++
			relPath := NormalizeRelativePath(path, targetDir)
			findings = append(findings, types.SecurityFinding{
				ID:          fmt.Sprintf("git-hygiene-env-%d", envIdx),
				Category:    types.CategorySecret,
				Tool:        "git-hygiene",
				Severity:    types.SeverityHigh,
				Title:       fmt.Sprintf("Committed environment file (%s)", name),
				Description: fmt.Sprintf("Environment file %s is present in the repository and may expose runtime secrets.", relPath),
				FilePath:    relPath,
				CWE:         "CWE-798",
			})
		}
		return nil
	})
	if err != nil {
		return findings, err
	}
	return findings, nil
}

func isBoundaryTSFile(relPath string) bool {
	lower := strings.ToLower(filepath.ToSlash(relPath))
	if !(strings.HasSuffix(lower, ".ts") || strings.HasSuffix(lower, ".tsx")) {
		return false
	}
	if strings.HasSuffix(lower, ".d.ts") || strings.HasSuffix(lower, ".spec.ts") || strings.HasSuffix(lower, ".test.ts") {
		return false
	}
	for _, seg := range []string{"controller", "auth", "guard", "middleware", "handler", "route", "security", "policy"} {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	return false
}

func ScanTypeScriptBoundarySafety(targetDir string) ([]types.SecurityFinding, error) {
	if targetDir == "" {
		return nil, nil
	}
	if _, err := os.Stat(targetDir); err != nil {
		return nil, nil
	}

	var findings []types.SecurityFinding
	idx := 0
	err := filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if path != targetDir && (skipHygieneDirs[name] || name == "test" || name == "tests" || name == "__tests__") {
				return filepath.SkipDir
			}
			return nil
		}
		relPath := NormalizeRelativePath(path, targetDir)
		if !isBoundaryTSFile(relPath) {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			var matched string
			switch {
			case strings.Contains(line, "@ts-ignore"):
				matched = "@ts-ignore"
			case strings.Contains(line, "@ts-expect-error"):
				matched = "@ts-expect-error"
			case strings.Contains(line, "as any"):
				matched = "as any"
			}
			if matched != "" {
				idx++
				findings = append(findings, types.SecurityFinding{
					ID:          fmt.Sprintf("ts-boundary-%d", idx),
					Category:    types.CategorySAST,
					Tool:        "ts-boundary",
					Severity:    types.SeverityMedium,
					Title:       fmt.Sprintf("Type safety bypass (%s) in security boundary", matched),
					Description: fmt.Sprintf("Found %q in boundary file %s:%d; type suppressions in auth/controller/guard boundaries can hide validation and authorization bugs.", matched, relPath, lineNum),
					FilePath:    relPath,
					Line:        lineNum,
					CWE:         "CWE-704",
				})
			}
		}
		return nil
	})
	if err != nil {
		return findings, err
	}
	return findings, nil
}

func detectBoilerplateLanguage(targetDir string) types.BoilerplateLanguage {
	if targetDir == "" {
		return ""
	}
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(targetDir, name))
		return err == nil
	}
	switch {
	case exists("go.mod"):
		return types.LangGo
	case exists("mix.exs"):
		return types.LangElixir
	case exists("pyproject.toml") || exists("requirements.txt") || exists("setup.py"):
		return types.LangPython
	case exists("tsconfig.json"):
		return types.LangTypeScript
	case exists("package.json"):
		return types.LangJavaScript
	default:
		return ""
	}
}

func findYARARuleFiles(targetDir string) []string {
	rulesDir := filepath.Join(targetDir, "rules", "yara")
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		lower := strings.ToLower(e.Name())
		if strings.HasSuffix(lower, ".yara") || strings.HasSuffix(lower, ".yar") {
			out = append(out, filepath.Join(rulesDir, e.Name()))
		}
	}
	return out
}

func canInvokeTool(mode runner.ExecutionMode, tool runner.ToolName, execFn runner.CommandExecutor) bool {
	if mode == runner.ModeDocker && runner.PinnedToolImage(tool) == "" {
		return false
	}
	if execFn != nil {
		return true
	}
	return runner.IsToolAvailable(mode, tool)
}

func runPolyglotTool(
	ctx context.Context,
	opts runner.ToolInvocationOptions,
	execFn runner.CommandExecutor,
	parseFn func([]byte, string) ([]types.SecurityFinding, error),
) ([]types.SecurityFinding, error) {
	if !canInvokeTool(opts.Mode, opts.Tool, execFn) {
		return nil, nil
	}
	res, err := runner.RunTool(ctx, opts, execFn)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s execution failed: %w", opts.Tool, err)
	}
	if strings.TrimSpace(res.Stdout) == "" {
		return nil, nil
	}
	return parseFn([]byte(res.Stdout), opts.TargetDir)
}

func runPolyglotScanners(
	ctx context.Context,
	targetDir string,
	lang types.BoilerplateLanguage,
	mode runner.ExecutionMode,
	execFn runner.CommandExecutor,
	scanPathFor func(runner.ToolName) string,
) ([]types.SecurityFinding, error) {
	var all []types.SecurityFinding

	switch lang {
	case types.LangGo:
		gosecFindings, err := runPolyglotTool(ctx, runner.ToolInvocationOptions{
			Tool:             runner.ToolGosec,
			Args:             []string{"-fmt=json", "-quiet", scanPathFor(runner.ToolGosec) + "/..."},
			TargetDir:        targetDir,
			Mode:             mode,
			AllowedExitCodes: []int{0, 1},
		}, execFn, ParseGosecOutput)
		if err != nil {
			return nil, err
		}
		all = append(all, gosecFindings...)

		gvFindings, err := runPolyglotTool(ctx, runner.ToolInvocationOptions{
			Tool:             runner.ToolGovulncheck,
			Args:             []string{"-json", "-C", scanPathFor(runner.ToolGovulncheck), "./..."},
			TargetDir:        targetDir,
			Mode:             mode,
			AllowedExitCodes: []int{0, 1, 3},
		}, execFn, ParseGovulncheckOutput)
		if err != nil {
			return nil, err
		}
		all = append(all, gvFindings...)

	case types.LangPython:
		banditFindings, err := runPolyglotTool(ctx, runner.ToolInvocationOptions{
			Tool:             runner.ToolBandit,
			Args:             []string{"-r", "-f", "json", "-q", scanPathFor(runner.ToolBandit)},
			TargetDir:        targetDir,
			Mode:             mode,
			AllowedExitCodes: []int{0, 1},
		}, execFn, ParseBanditOutput)
		if err != nil {
			return nil, err
		}
		all = append(all, banditFindings...)

	case types.LangElixir:
		sobelowFindings, err := runPolyglotTool(ctx, runner.ToolInvocationOptions{
			Tool:             runner.ToolSobelow,
			Args:             []string{"--format", "json", "--root", scanPathFor(runner.ToolSobelow)},
			TargetDir:        targetDir,
			Mode:             mode,
			AllowedExitCodes: []int{0, 1},
		}, execFn, ParseSobelowOutput)
		if err != nil {
			return nil, err
		}
		all = append(all, sobelowFindings...)

	case types.LangTypeScript, types.LangJavaScript:
		tsFindings, err := ScanTypeScriptBoundarySafety(targetDir)
		if err != nil {
			return all, err
		}
		all = append(all, tsFindings...)
	}

	if yaraRules := findYARARuleFiles(targetDir); len(yaraRules) > 0 && canInvokeTool(mode, runner.ToolYARA, execFn) {
		scanRoot := scanPathFor(runner.ToolYARA)
		for _, ruleFile := range yaraRules {
			ruleArg := ruleFile
			if runner.ResolveEffectiveMode(mode, runner.ToolYARA) == runner.ModeDocker {
				ruleArg = "/workspace/" + NormalizeRelativePath(ruleFile, targetDir)
			}
			yaraFindings, err := runPolyglotTool(ctx, runner.ToolInvocationOptions{
				Tool:             runner.ToolYARA,
				Args:             []string{"-r", ruleArg, scanRoot},
				TargetDir:        targetDir,
				Mode:             mode,
				AllowedExitCodes: []int{0, 1},
			}, execFn, ParseYARAOutput)
			if err != nil {
				return nil, err
			}
			all = append(all, yaraFindings...)
		}
	}

	return all, nil
}
