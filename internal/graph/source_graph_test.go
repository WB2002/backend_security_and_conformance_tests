package graph_test

import (
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/graph"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func hasEdge(edges []types.GraphEdge, from, to string) bool {
	for _, e := range edges {
		if e.From == from && e.To == to {
			return true
		}
	}
	return false
}

func TestPolyglotSourceGraphBuilder(t *testing.T) {
	t.Run("TypeScript/JS ESM imports, NodeNext .js->.ts, and tsconfig path aliases", func(t *testing.T) {
		g := graph.BuildSourceGraphFromFiles(map[string]string{
			"src/auth/auth.service.ts": `
				import { UsersService } from '../users/users.service.js';
				import { signJwt } from '@/crypto/jwt';
			`,
			"src/users/users.service.ts": `
				import { AuthService } from '../auth/auth.service.js';
			`,
			"src/crypto/jwt.ts": `
				import crypto from 'node:crypto';
				export const signJwt = () => {};
			`,
		}, graph.SourceGraphOptions{
			Language:      types.LangTypeScript,
			TSPathAliases: map[string][]string{"@/*": {"src/*"}},
		})

		if !hasEdge(g.Edges, "src/auth/auth.service.ts", "src/users/users.service.ts") ||
			!hasEdge(g.Edges, "src/auth/auth.service.ts", "src/crypto/jwt.ts") ||
			!hasEdge(g.Edges, "src/users/users.service.ts", "src/auth/auth.service.ts") {
			t.Fatalf("missing expected TS edges in %+v", g.Edges)
		}
	})

	t.Run("Go native go/parser package imports with go.mod prefix", func(t *testing.T) {
		g := graph.BuildSourceGraphFromFiles(map[string]string{
			"internal/auth/service.go": `
				package auth
				import (
					"fmt"
					"github.com/acme/app/internal/users"
				)
			`,
			"internal/users/repo.go": `
				package users
				import "github.com/acme/app/internal/auth"
			`,
		}, graph.SourceGraphOptions{
			Language:     types.LangGo,
			GoModuleName: "github.com/acme/app",
		})

		if !hasEdge(g.Edges, "internal/auth/service.go", "internal/users/repo.go") ||
			!hasEdge(g.Edges, "internal/users/repo.go", "internal/auth/service.go") {
			t.Fatalf("missing expected Go edges in %+v", g.Edges)
		}
	})

	t.Run("Python absolute and relative from-imports", func(t *testing.T) {
		g := graph.BuildSourceGraphFromFiles(map[string]string{
			"app/auth/service.py": `
import os
from app.users import repository
from .tokens import verify_token
`,
			"app/auth/tokens.py": `
from app.users.repository import get_user
`,
			"app/users/repository.py": `
from app.auth.service import authenticate
`,
		}, graph.SourceGraphOptions{Language: types.LangPython})

		if !hasEdge(g.Edges, "app/auth/service.py", "app/users/repository.py") ||
			!hasEdge(g.Edges, "app/auth/service.py", "app/auth/tokens.py") ||
			!hasEdge(g.Edges, "app/users/repository.py", "app/auth/service.py") {
			t.Fatalf("missing expected Python edges in %+v", g.Edges)
		}
	})

	t.Run("Elixir defmodule index, multi-alias {A, B}, import/use, and remote calls", func(t *testing.T) {
		g := graph.BuildSourceGraphFromFiles(map[string]string{
			"lib/my_app/auth/guardian.ex": `
defmodule MyApp.Auth.Guardian do
  use Joken.Config
  alias MyApp.Accounts.{User, Permissions}
  def verify(token), do: MyApp.Accounts.User.find(token)
end
`,
			"lib/my_app/accounts/user.ex": `
defmodule MyApp.Accounts.User do
  import MyApp.Auth.Guardian
  def find(id), do: id
end
`,
			"lib/my_app/accounts/permissions.ex": `
defmodule MyApp.Accounts.Permissions do
  def check(), do: :ok
end
`,
		}, graph.SourceGraphOptions{Language: types.LangElixir})

		if !hasEdge(g.Edges, "lib/my_app/auth/guardian.ex", "lib/my_app/accounts/user.ex") ||
			!hasEdge(g.Edges, "lib/my_app/auth/guardian.ex", "lib/my_app/accounts/permissions.ex") ||
			!hasEdge(g.Edges, "lib/my_app/accounts/user.ex", "lib/my_app/auth/guardian.ex") {
			t.Fatalf("missing expected Elixir edges in %+v", g.Edges)
		}
	})
}
