package dast

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/runner"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

type zapDoc struct {
	Site []struct {
		Name   string `json:"@name"`
		Alerts []struct {
			PluginID  string `json:"pluginid"`
			Alert     string `json:"alert"`
			RiskCode  string `json:"riskcode"`
			Desc      string `json:"desc"`
			CWEID     string `json:"cweid"`
			Instances []struct {
				URI    string `json:"uri"`
				Method string `json:"method"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

func mapZAPRiskCode(code string) types.Severity {
	switch strings.TrimSpace(code) {
	case "3":
		return types.SeverityHigh
	case "2":
		return types.SeverityMedium
	case "1":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

func ParseZAPJSONOutput(rawJSON []byte) ([]types.SecurityFinding, error) {
	if len(strings.TrimSpace(string(rawJSON))) == 0 {
		return nil, nil
	}
	var doc zapDoc
	if err := json.Unmarshal(rawJSON, &doc); err != nil {
		return nil, fmt.Errorf("parse zap json: %w", err)
	}
	var findings []types.SecurityFinding
	for _, s := range doc.Site {
		for i, a := range s.Alerts {
			endpoint := s.Name
			if len(a.Instances) > 0 {
				inst := a.Instances[0]
				if inst.Method != "" {
					endpoint = fmt.Sprintf("%s %s", inst.Method, inst.URI)
				} else {
					endpoint = inst.URI
				}
			}
			cwe := ""
			if a.CWEID != "" && a.CWEID != "-1" && a.CWEID != "0" {
				cwe = "CWE-" + a.CWEID
			}
			findings = append(findings, types.SecurityFinding{
				ID:          fmt.Sprintf("zap-%s-%d", a.PluginID, i+1),
				Category:    types.CategoryDAST,
				Tool:        "zap",
				Severity:    mapZAPRiskCode(a.RiskCode),
				Title:       a.Alert,
				Description: a.Desc,
				Endpoint:    endpoint,
				CWE:         cwe,
			})
		}
	}
	return findings, nil
}

type nucleiLine struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
	MatchedAt string `json:"matched-at"`
}

func mapNucleiSeverity(raw string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

func ParseNucleiJSONLOutput(rawJSONL []byte) ([]types.SecurityFinding, error) {
	scanner := bufio.NewScanner(bytes.NewReader(rawJSONL))
	var findings []types.SecurityFinding
	idx := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var item nucleiLine
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			return nil, fmt.Errorf("parse nuclei jsonl line: %w", err)
		}
		idx++
		findings = append(findings, types.SecurityFinding{
			ID:          fmt.Sprintf("nuclei-%s-%d", item.TemplateID, idx),
			Category:    types.CategoryDAST,
			Tool:        "nuclei",
			Severity:    mapNucleiSeverity(item.Info.Severity),
			Title:       item.Info.Name,
			Description: item.Info.Description,
			Endpoint:    item.MatchedAt,
		})
	}
	return findings, nil
}

var schemathesisHeaderRe = regexp.MustCompile(`(?m)^_\s+([A-Z]+\s+\S+)\s+_$`)

func ParseSchemathesisOutput(stdout string, exitCode int) []types.SecurityFinding {
	if exitCode == 0 && !strings.Contains(stdout, "=== FAILURES ===") {
		return nil
	}
	matches := schemathesisHeaderRe.FindAllStringSubmatch(stdout, -1)
	var findings []types.SecurityFinding
	for i, m := range matches {
		ep := strings.TrimSpace(m[1])
		findings = append(findings, types.SecurityFinding{
			ID:          fmt.Sprintf("schemathesis-%d", i+1),
			Category:    types.CategoryDAST,
			Tool:        "schemathesis",
			Severity:    types.SeverityHigh,
			Title:       fmt.Sprintf("OpenAPI fuzzing failure on %s", ep),
			Description: "Schemathesis property-based API fuzzing triggered a 5xx or schema conformance error",
			Endpoint:    ep,
		})
	}
	if len(findings) == 0 && exitCode != 0 {
		findings = append(findings, types.SecurityFinding{
			ID:          "schemathesis-1",
			Category:    types.CategoryDAST,
			Tool:        "schemathesis",
			Severity:    types.SeverityHigh,
			Title:       "OpenAPI Schemathesis fuzzing failure",
			Description: strings.TrimSpace(stdout),
		})
	}
	return findings
}

func RunDASTSuite(ctx context.Context, baseURL string, openapiURL string, mode runner.ExecutionMode, execFn runner.CommandExecutor) ([]types.SecurityFinding, error) {
	var all []types.SecurityFinding
	targetBase := strings.TrimRight(baseURL, "/")
	if mode == runner.ModeDocker {
		targetBase = runner.RewriteURLForDocker(targetBase)
	}

	fullOpenAPI := openapiURL
	if fullOpenAPI != "" && !strings.HasPrefix(fullOpenAPI, "http://") && !strings.HasPrefix(fullOpenAPI, "https://") {
		if !strings.HasPrefix(fullOpenAPI, "/") {
			fullOpenAPI = "/" + fullOpenAPI
		}
		fullOpenAPI = targetBase + fullOpenAPI
	} else if mode == runner.ModeDocker && fullOpenAPI != "" {
		fullOpenAPI = runner.RewriteURLForDocker(fullOpenAPI)
	}

	nucleiRes, err := runner.RunTool(ctx, runner.ToolInvocationOptions{
		Tool:             runner.ToolNuclei,
		Args:             []string{"-u", targetBase, "-jsonl", "-silent"},
		Mode:             mode,
		AllowedExitCodes: []int{0, 1},
	}, execFn)
	if err == nil && strings.TrimSpace(nucleiRes.Stdout) != "" {
		if f, pErr := ParseNucleiJSONLOutput([]byte(nucleiRes.Stdout)); pErr == nil {
			all = append(all, f...)
		}
	}

	if fullOpenAPI != "" {
		zapRes, zErr := runner.RunTool(ctx, runner.ToolInvocationOptions{
			Tool:             runner.ToolZAP,
			Args:             []string{"zap-api-scan.py", "-t", fullOpenAPI, "-f", "openapi", "-J", "-"},
			Mode:             mode,
			AllowedExitCodes: []int{0, 1, 2},
		}, execFn)
		if zErr == nil && strings.TrimSpace(zapRes.Stdout) != "" {
			if f, pErr := ParseZAPJSONOutput([]byte(zapRes.Stdout)); pErr == nil {
				all = append(all, f...)
			}
		}

		schemaRes, sErr := runner.RunTool(ctx, runner.ToolInvocationOptions{
			Tool:             runner.ToolSchemathesis,
			Args:             []string{"run", fullOpenAPI, "--checks", "all"},
			Mode:             mode,
			AllowedExitCodes: []int{0, 1},
		}, execFn)
		if sErr == nil {
			all = append(all, ParseSchemathesisOutput(schemaRes.Stdout, schemaRes.ExitCode)...)
		}
	}

	return all, nil
}
