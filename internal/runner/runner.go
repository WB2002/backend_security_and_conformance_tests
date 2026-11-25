package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	LocalBinary      string
	DockerImage      string
	DockerCommand    []string
	NeedsHostGateway bool
	DefaultOffline   bool
}

var toolRegistry = map[ToolName]toolSpec{
	ToolSemgrep:      {LocalBinary: "semgrep", DockerImage: "semgrep/semgrep:1.102.0@sha256:cef085245254d15c66d96be413c730f0b458823a1d0c39afbc12f705b664ce8f", DockerCommand: []string{"semgrep"}},
	ToolGitleaks:     {LocalBinary: "gitleaks", DockerImage: "zricethezav/gitleaks:v8.21.2@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46", DefaultOffline: true},
	ToolTrivy:        {LocalBinary: "trivy", DockerImage: "aquasec/trivy:0.58.1@sha256:ab70a02200597efa04748f210f793936eb647cbcdb0ea69cc30b226d6f5a22c7"},
	ToolCdxgen:       {LocalBinary: "cdxgen", DockerImage: "ghcr.io/cyclonedx/cdxgen-node20:v11.1.0@sha256:3dda0e862456a4b345c8c7e446b003ed3c0ebd1490b017382e0336b789fab878"},
	ToolOSVScanner:   {LocalBinary: "osv-scanner", DockerImage: "ghcr.io/google/osv-scanner:v1.9.1@sha256:36dea1baa2b34df3ee911d712e6a774eff04cc8b25789e0e6837d40759afaeab"},
	ToolZAP:          {LocalBinary: "zap.sh", DockerImage: "ghcr.io/zaproxy/zaproxy:2.16.0@sha256:391f66efa53b30de40d4a1c6e28146477263552fc828bc7613c9cd11a2949908", NeedsHostGateway: true},
	ToolNuclei:       {LocalBinary: "nuclei", DockerImage: "projectdiscovery/nuclei:v3.3.8@sha256:3c37049ecfd2d3230add2e7308249f694bcb43cfe243d090d6046cd6c35ff855", NeedsHostGateway: true},
	ToolSchemathesis: {LocalBinary: "schemathesis", DockerImage: "schemathesis/schemathesis:v3.39.8@sha256:d1d7f848c09f1cb270e421a0803a5722bcd898bbb2f365a8a5172e24b4dbbf5d", NeedsHostGateway: true},
	ToolK6:           {LocalBinary: "k6", DockerImage: "grafana/k6:0.55.0@sha256:b24f418fc99a26dd57904c952c03bfaf79462be18508acc45aafa07ff68e7df2", NeedsHostGateway: true},
}

func PinnedToolImage(tool ToolName) string {
	return toolRegistry[tool].DockerImage
}

func CreateIsolatedWorkDir(prefix string) (parentDir string, outDir string, err error) {
	parentDir, err = os.MkdirTemp("", prefix)
	if err != nil {
		return "", "", err
	}
	if err := os.Chmod(parentDir, 0o700); err != nil {
		_ = os.RemoveAll(parentDir)
		return "", "", err
	}
	outDir = filepath.Join(parentDir, "out")
	if err := os.MkdirAll(outDir, 0o777); err != nil {
		_ = os.RemoveAll(parentDir)
		return "", "", err
	}
	if err := os.Chmod(outDir, 0o777); err != nil {
		_ = os.RemoveAll(parentDir)
		return "", "", err
	}
	return parentDir, outDir, nil
}

type ToolInvocationOptions struct {
	Tool             ToolName
	Args             []string
	TargetDir        string
	WorkDir          string
	Mode             ExecutionMode
	AllowedExitCodes []int
	Env              []string
	NetworkDisabled  bool
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

func ResolveEffectiveMode(mode ExecutionMode, tool ToolName) ExecutionMode {
	if mode == ModeDocker || mode == ModeLocal {
		return mode
	}
	spec := toolRegistry[tool]
	if _, err := exec.LookPath("docker"); err == nil {
		if _, localErr := exec.LookPath(spec.LocalBinary); localErr == nil {
			// If local binary also exists, verify docker daemon is reachable before choosing docker
			if err := exec.Command("docker", "info").Run(); err != nil {
				return ModeLocal
			}
		}
		return ModeDocker
	}
	if spec.LocalBinary != "" {
		if _, err := exec.LookPath(spec.LocalBinary); err == nil {
			return ModeLocal
		}
	}
	return ModeDocker
}

func BuildToolInvocation(opts ToolInvocationOptions) (ResolvedCommand, error) {
	spec, ok := toolRegistry[opts.Tool]
	if !ok {
		return ResolvedCommand{}, fmt.Errorf("unknown tool %q", opts.Tool)
	}
	effectiveMode := ResolveEffectiveMode(opts.Mode, opts.Tool)
	if effectiveMode == ModeLocal {
		return ResolvedCommand{
			Binary: spec.LocalBinary,
			Args:   slices.Clone(opts.Args),
			Mode:   ModeLocal,
		}, nil
	}

	dockerArgs := []string{
		"run", "--rm",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--pids-limit=512",
	}
	offline := opts.NetworkDisabled || spec.DefaultOffline
	if spec.NeedsHostGateway && !offline {
		dockerArgs = append(dockerArgs, "--add-host=host.docker.internal:host-gateway")
	}
	if offline {
		dockerArgs = append(dockerArgs, "--network=none")
	}
	if opts.TargetDir != "" {
		absTarget := opts.TargetDir
		if abs, err := filepath.Abs(opts.TargetDir); err == nil {
			absTarget = abs
		}
		dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/workspace:ro", absTarget))
	}
	if opts.WorkDir != "" {
		absWork := opts.WorkDir
		if abs, err := filepath.Abs(opts.WorkDir); err == nil {
			absWork = abs
		}
		mountTarget := "/out"
		if opts.Tool == ToolZAP {
			mountTarget = "/zap/wrk"
		}
		dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:%s:rw", absWork, mountTarget))
	}
	for _, kv := range opts.Env {
		dockerArgs = append(dockerArgs, "-e", kv)
	}
	dockerArgs = append(dockerArgs, spec.DockerImage)
	dockerArgs = append(dockerArgs, spec.DockerCommand...)
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
