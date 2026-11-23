package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"slices"
	"strings"
)

type ToolName string

const (
	ToolSemgrep      ToolName = "semgrep"
	ToolGitleaks     ToolName = "gitleaks"
	ToolTrivy        ToolName = "trivy"
	ToolCdxgen       ToolName = "cdxgen"
	ToolOSVScanner   ToolName = "osv-scanner"
	ToolZAP          ToolName = "zap"
	ToolNuclei       ToolName = "nuclei"
	ToolSchemathesis ToolName = "schemathesis"
	ToolK6           ToolName = "k6"
)

type ExecutionMode string

const (
	ModeAuto   ExecutionMode = "auto"
	ModeDocker ExecutionMode = "docker"
	ModeLocal  ExecutionMode = "local"
)

type toolSpec struct {
	LocalBinary string
	DockerImage string
}

var toolRegistry = map[ToolName]toolSpec{
	ToolSemgrep:      {LocalBinary: "semgrep", DockerImage: "semgrep/semgrep:1.102.0"},
	ToolGitleaks:     {LocalBinary: "gitleaks", DockerImage: "zricethezav/gitleaks:v8.21.2"},
	ToolTrivy:        {LocalBinary: "trivy", DockerImage: "aquasec/trivy:0.58.1"},
	ToolCdxgen:       {LocalBinary: "cdxgen", DockerImage: "ghcr.io/cyclonedx/cdxgen:v11.1.0"},
	ToolOSVScanner:   {LocalBinary: "osv-scanner", DockerImage: "ghcr.io/google/osv-scanner:v1.9.1"},
	ToolZAP:          {LocalBinary: "zap.sh", DockerImage: "ghcr.io/zaproxy/zaproxy:stable"},
	ToolNuclei:       {LocalBinary: "nuclei", DockerImage: "projectdiscovery/nuclei:v3.3.7"},
	ToolSchemathesis: {LocalBinary: "schemathesis", DockerImage: "schemathesis/schemathesis:stable"},
	ToolK6:           {LocalBinary: "k6", DockerImage: "grafana/k6:0.55.0"},
}

type ToolInvocationOptions struct {
	Tool             ToolName
	Args             []string
	TargetDir        string
	WorkDir          string
	Mode             ExecutionMode
	AllowedExitCodes []int
	Env              []string
}

type ResolvedCommand struct {
	Binary string
	Args   []string
	Mode   ExecutionMode
}

type ToolExecutionResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	OK       bool
	Mode     ExecutionMode
}

type CommandExecutor func(ctx context.Context, cmd ResolvedCommand) (ToolExecutionResult, error)

func RewriteURLForDocker(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		res := strings.ReplaceAll(rawURL, "127.0.0.1", "host.docker.internal")
		return strings.ReplaceAll(res, "localhost", "host.docker.internal")
	}
	host := u.Hostname()
	if host == "127.0.0.1" || host == "localhost" {
		if port := u.Port(); port != "" {
			u.Host = "host.docker.internal:" + port
		} else {
			u.Host = "host.docker.internal"
		}
	}
	return u.String()
}

func resolveMode(mode ExecutionMode, spec toolSpec) ExecutionMode {
	if mode == ModeDocker || mode == ModeLocal {
		return mode
	}
	if _, err := exec.LookPath("docker"); err == nil {
		return ModeDocker
	}
	if _, err := exec.LookPath(spec.LocalBinary); err == nil {
		return ModeLocal
	}
	return ModeDocker
}

func BuildToolInvocation(opts ToolInvocationOptions) (ResolvedCommand, error) {
	spec, ok := toolRegistry[opts.Tool]
	if !ok {
		return ResolvedCommand{}, fmt.Errorf("unknown tool %q", opts.Tool)
	}
	effectiveMode := resolveMode(opts.Mode, spec)
	if effectiveMode == ModeLocal {
		return ResolvedCommand{
			Binary: spec.LocalBinary,
			Args:   slices.Clone(opts.Args),
			Mode:   ModeLocal,
		}, nil
	}

	dockerArgs := []string{"run", "--rm", "--add-host=host.docker.internal:host-gateway"}
	if opts.TargetDir != "" {
		dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/workspace:ro", opts.TargetDir))
	}
	if opts.WorkDir != "" {
		dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/out:rw", opts.WorkDir))
	}
	for _, kv := range opts.Env {
		dockerArgs = append(dockerArgs, "-e", kv)
	}
	dockerArgs = append(dockerArgs, spec.DockerImage)
	dockerArgs = append(dockerArgs, opts.Args...)

	return ResolvedCommand{
		Binary: "docker",
		Args:   dockerArgs,
		Mode:   ModeDocker,
	}, nil
}

func DefaultCommandExecutor(ctx context.Context, cmd ResolvedCommand) (ToolExecutionResult, error) {
	c := exec.CommandContext(ctx, cmd.Binary, cmd.Args...)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return ToolExecutionResult{
				ExitCode: -1,
				Stdout:   stdout.String(),
				Stderr:   stderr.String(),
				Mode:     cmd.Mode,
			}, err
		}
	}
	return ToolExecutionResult{
		ExitCode: exitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Mode:     cmd.Mode,
	}, nil
}

func RunTool(ctx context.Context, opts ToolInvocationOptions, execFn CommandExecutor) (ToolExecutionResult, error) {
	cmd, err := BuildToolInvocation(opts)
	if err != nil {
		return ToolExecutionResult{}, err
	}
	if execFn == nil {
		execFn = DefaultCommandExecutor
	}
	res, err := execFn(ctx, cmd)
	if err != nil {
		return res, err
	}
	allowed := opts.AllowedExitCodes
	if len(allowed) == 0 {
		allowed = []int{0, 1}
	}
	res.Mode = cmd.Mode
	if slices.Contains(allowed, res.ExitCode) {
		res.OK = true
		return res, nil
	}
	res.OK = false
	return res, fmt.Errorf("tool %s exited with disallowed code %d: %s", opts.Tool, res.ExitCode, strings.TrimSpace(res.Stderr))
}
