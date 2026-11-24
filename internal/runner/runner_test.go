package runner_test

import (
	"context"
	"slices"
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
	if !slices.Contains(cmd.Args, "semgrep/semgrep:1.102.0") {
		t.Fatalf("expected pinned semgrep image in %v", cmd.Args)
	}
	imgIdx := slices.Index(cmd.Args, "semgrep/semgrep:1.102.0")
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
	if !slices.Contains(cdxCmd.Args, "ghcr.io/cyclonedx/cdxgen-node20:v11.1.0") {
		t.Fatalf("expected lightweight cdxgen-node20 image in %v", cdxCmd.Args)
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

