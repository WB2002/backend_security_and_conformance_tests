package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func isSupportedLanguage(lang types.BoilerplateLanguage) bool {
	switch lang {
	case types.LangTypeScript, types.LangJavaScript, types.LangGo, types.LangPython, types.LangElixir:
		return true
	default:
		return false
	}
}

func ParseAndValidateManifest(data []byte) (types.BoilerplateManifest, error) {
	var m types.BoilerplateManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("invalid manifest JSON: %w", err)
	}
	m.Name = strings.TrimSpace(m.Name)
	if m.Name == "" {
		return m, fmt.Errorf("manifest name is required")
	}
	if !isSupportedLanguage(m.Language) {
		return m, fmt.Errorf("unsupported boilerplate language %q", m.Language)
	}
	if strings.TrimSpace(m.Capabilities.Health.Path) == "" {
		return m, fmt.Errorf("capabilities.health.path is required")
	}
	if m.Capabilities.Health.Method == "" {
		m.Capabilities.Health.Method = "GET"
	}

	if m.Capabilities.Auth != nil {
		if m.Capabilities.Auth.Register.Method == "" {
			m.Capabilities.Auth.Register.Method = "POST"
		}
		if m.Capabilities.Auth.Register.EmailField == "" {
			m.Capabilities.Auth.Register.EmailField = "email"
		}
		if m.Capabilities.Auth.Register.PasswordField == "" {
			m.Capabilities.Auth.Register.PasswordField = "password"
		}
		if m.Capabilities.Auth.Login.Method == "" {
			m.Capabilities.Auth.Login.Method = "POST"
		}
		if m.Capabilities.Auth.Login.EmailField == "" {
			m.Capabilities.Auth.Login.EmailField = "email"
		}
		if m.Capabilities.Auth.Login.PasswordField == "" {
			m.Capabilities.Auth.Login.PasswordField = "password"
		}
		if m.Capabilities.Auth.Login.TokenPath == "" {
			m.Capabilities.Auth.Login.TokenPath = "accessToken"
		}
		if m.Capabilities.Auth.Me.Method == "" {
			m.Capabilities.Auth.Me.Method = "GET"
		}
		if m.Capabilities.Auth.Me.UserIDPath == "" {
			m.Capabilities.Auth.Me.UserIDPath = "id"
		}
	}

	if m.Capabilities.CRUD != nil && m.Capabilities.CRUD.IDPath == "" {
		m.Capabilities.CRUD.IDPath = "id"
	}

	if m.Capabilities.RBAC != nil && m.Capabilities.RBAC.AdminMethod == "" {
		m.Capabilities.RBAC.AdminMethod = "GET"
	}

	if m.Capabilities.SSRFTest != nil && m.Capabilities.SSRFTest.Method == "" {
		m.Capabilities.SSRFTest.Method = "POST"
	}

	if m.Capabilities.RateLimit != nil && m.Capabilities.RateLimit.LoginBurstCount <= 0 {
		m.Capabilities.RateLimit.LoginBurstCount = 25
	}

	return m, nil
}

func LoadManifest(filePath string) (types.BoilerplateManifest, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return types.BoilerplateManifest{}, err
	}
	return ParseAndValidateManifest(b)
}

func ExtractByPath(payload any, dotPath string) (any, bool) {
	cleaned := strings.TrimSpace(dotPath)
	cleaned = strings.TrimPrefix(cleaned, "$.")
	cleaned = strings.TrimPrefix(cleaned, "$")
	cleaned = strings.TrimPrefix(cleaned, ".")
	if cleaned == "" {
		return payload, payload != nil
	}

	segments := strings.Split(cleaned, ".")
	curr := payload
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		m, ok := curr.(map[string]any)
		if !ok {
			return nil, false
		}
		val, exists := m[seg]
		if !exists {
			return nil, false
		}
		curr = val
	}
	return curr, true
}
