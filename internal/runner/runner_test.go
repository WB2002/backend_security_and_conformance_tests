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
