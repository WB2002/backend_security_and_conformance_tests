package runner_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/runner"
)

func TestHybridToolRunner(t *testing.T) {
	if got := runner.RewriteURLForDocker("http://127.0.0.1:3000/api"); got != "http://host.docker.internal:3000/api" {
		t.Fatalf("expected host.docker.internal rewrite, got %s", got)
	}
	if got := runner.RewriteURLForDocker("http://localhost:8080"); got != "http://host.docker.internal:8080" {
		t.Fatalf("expected localhost rewrite, got %s", got)
	}

	cmd, err := runner.BuildToolInvocation(runner.ToolInvocationOptions{
		Tool:      runner.ToolSemgrep,
		Args:      []string{"scan", "--config", "auto", "--json", "/workspace"},
		TargetDir: "/Users/pc/my-repo",
		Mode:      runner.ModeDocker,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Binary != "docker" {
		t.Fatalf("expected docker binary, got %s", cmd.Binary)
	}
	if !slices.Contains(cmd.Args, "/Users/pc/my-repo:/workspace:ro") {
		t.Fatalf("expected read-only workspace mount in %v", cmd.Args)
	}
	semgrepImg := runner.PinnedToolImage(runner.ToolSemgrep)
	if !slices.Contains(cmd.Args, semgrepImg) {
		t.Fatalf("expected pinned semgrep image %s in %v", semgrepImg, cmd.Args)
	}
	imgIdx := slices.Index(cmd.Args, semgrepImg)
	if imgIdx < 0 || imgIdx+2 >= len(cmd.Args) || cmd.Args[imgIdx+1] != "semgrep" || cmd.Args[imgIdx+2] != "scan" {
		t.Fatalf("expected docker semgrep invocation to prefix 'semgrep' before 'scan', got %v", cmd.Args)
	}

	cdxCmd, err := runner.BuildToolInvocation(runner.ToolInvocationOptions{
		Tool:      runner.ToolCdxgen,
		Args:      []string{"-r", "-o", "/out/bom.json", "/workspace"},
		TargetDir: "/Users/pc/my-repo",
		WorkDir:   "/tmp/out",
		Mode:      runner.ModeDocker,
	})
	if err != nil {
		t.Fatalf("unexpected cdxgen error: %v", err)
	}
	cdxImg := runner.PinnedToolImage(runner.ToolCdxgen)
	if !slices.Contains(cdxCmd.Args, cdxImg) {
		t.Fatalf("expected lightweight cdxgen-node20 image %s in %v", cdxImg, cdxCmd.Args)
	}

	res, err := runner.RunTool(context.Background(), runner.ToolInvocationOptions{
		Tool:             runner.ToolGitleaks,
		Args:             []string{"detect"},
		Mode:             runner.ModeLocal,
		AllowedExitCodes: []int{0, 1},
	}, func(ctx context.Context, c runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		return runner.ToolExecutionResult{
			ExitCode: 1,
			Stdout:   `[{"RuleID":"aws-key"}]`,
		}, nil
	})
	if err != nil || !res.OK || res.ExitCode != 1 {
		t.Fatalf("expected exit code 1 to be treated as non-fatal OK when allowed: res=%+v err=%v", res, err)
	}
}

func TestResolveModeAndRelativeMount(t *testing.T) {
	cmd, err := runner.BuildToolInvocation(runner.ToolInvocationOptions{
		Tool:      runner.ToolSemgrep,
		Args:      []string{"scan", "/workspace"},
		TargetDir: ".",
		WorkDir:   ".",
		Mode:      runner.ModeDocker,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, a := range cmd.Args {
		if a == "-v" && i+1 < len(cmd.Args) {
			mount := cmd.Args[i+1]
			if mount[0] != '/' {
				t.Fatalf("expected absolute host path in docker volume mount, got %s", mount)
			}
		}
	}
}

func TestCreateIsolatedWorkDirAndHardenedDockerInvocation(t *testing.T) {
	parentDir, outDir, err := runner.CreateIsolatedWorkDir("conformance-test-")
	if err != nil {
		t.Fatalf("CreateIsolatedWorkDir failed: %v", err)
	}
	defer os.RemoveAll(parentDir)

	pInfo, err := os.Stat(parentDir)
	if err != nil || pInfo.Mode().Perm() != 0o700 {
		t.Fatalf("expected 0700 parent dir, got %v (err=%v)", pInfo.Mode().Perm(), err)
	}
	oInfo, err := os.Stat(outDir)
	if err != nil || oInfo.Mode().Perm()&0o007 != 0o007 {
		t.Fatalf("expected world-writable child outDir inside 0700 parent for non-root container UIDs, got %o", oInfo.Mode().Perm())
	}

	// White-box offline tool (Gitleaks): digest-pinned, cap-drop ALL, no-new-privileges, network=none, NO host.docker.internal
	gCmd, err := runner.BuildToolInvocation(runner.ToolInvocationOptions{
		Tool:      runner.ToolGitleaks,
		Args:      []string{"detect", "--source", "/workspace"},
		TargetDir: "/Users/pc/my-repo",
		Mode:      runner.ModeDocker,
	})
	if err != nil {
		t.Fatalf("BuildToolInvocation gitleaks failed: %v", err)
	}
	for _, mustHave := range []string{"--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=512", "--network=none"} {
		if !slices.Contains(gCmd.Args, mustHave) {
			t.Fatalf("expected %s in gitleaks docker args: %v", mustHave, gCmd.Args)
		}
	}
	if slices.Contains(gCmd.Args, "--add-host=host.docker.internal:host-gateway") {
		t.Fatalf("repo scanner must NOT map host.docker.internal: %v", gCmd.Args)
	}
	if !strings.Contains(runner.PinnedToolImage(runner.ToolZAP), "ghcr.io/zaproxy/zaproxy:2.16.0@sha256:") ||
		!strings.Contains(runner.PinnedToolImage(runner.ToolNuclei), "projectdiscovery/nuclei:v3.3.8@sha256:") ||
		!strings.Contains(runner.PinnedToolImage(runner.ToolSchemathesis), "schemathesis/schemathesis:v3.39.8@sha256:") {
		t.Fatalf("expected pinned non-stable @sha256 images for ZAP, Nuclei, Schemathesis")
	}

	// Explicit NetworkDisabled override on a normally networked tool
	offlineCmd, err := runner.BuildToolInvocation(runner.ToolInvocationOptions{
		Tool:            runner.ToolSemgrep,
		Args:            []string{"scan", "/workspace"},
		TargetDir:       "/Users/pc/my-repo",
		Mode:            runner.ModeDocker,
		NetworkDisabled: true,
	})
	if err != nil || !slices.Contains(offlineCmd.Args, "--network=none") {
		t.Fatalf("expected --network=none when NetworkDisabled=true: %v (err=%v)", offlineCmd.Args, err)
	}

	// Dynamic network tool (Nuclei): MUST map host.docker.internal and NOT set --network=none
	nCmd, err := runner.BuildToolInvocation(runner.ToolInvocationOptions{
		Tool: runner.ToolNuclei,
		Args: []string{"-u", "http://host.docker.internal:3000"},
		Mode: runner.ModeDocker,
	})
	if err != nil || !slices.Contains(nCmd.Args, "--add-host=host.docker.internal:host-gateway") || slices.Contains(nCmd.Args, "--network=none") {
		t.Fatalf("expected host.docker.internal mapping and network enabled for nuclei: %v (err=%v)", nCmd.Args, err)
	}
}

