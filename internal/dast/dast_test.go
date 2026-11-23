package dast_test

import (
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/dast"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestDASTParsers(t *testing.T) {
	zapJSON := []byte(`{
  "site": [
    {
      "@name": "http://127.0.0.1:3000",
      "alerts": [
        {
          "pluginid": "10038",
          "alert": "Content Security Policy (CSP) Header Not Set",
          "riskcode": "2",
          "desc": "CSP header missing",
          "cweid": "693",
          "instances": [{ "uri": "http://127.0.0.1:3000/api/v1/users", "method": "GET" }]
        }
      ]
    }
  ]
}`)
	zFindings, err := dast.ParseZAPJSONOutput(zapJSON)
	if err != nil || len(zFindings) != 1 || zFindings[0].Severity != types.SeverityMedium || zFindings[0].CWE != "CWE-693" {
		t.Fatalf("zap parse failed: err=%v findings=%+v", err, zFindings)
	}

	nucleiJSONL := []byte(`{"template-id":"cors-misconfig","info":{"name":"Arbitrary Origin CORS Reflection","severity":"high","description":"Reflects Origin"},"matched-at":"http://127.0.0.1:3000/api/v1/auth/login"}` + "\n")
	nFindings, err := dast.ParseNucleiJSONLOutput(nucleiJSONL)
	if err != nil || len(nFindings) != 1 || nFindings[0].Severity != types.SeverityHigh {
		t.Fatalf("nuclei parse failed: err=%v findings=%+v", err, nFindings)
	}

	schemaOut := `
=== FAILURES ===
_ POST /api/v1/projects _
- Server error: 500 Internal Server Error
`
	sFindings := dast.ParseSchemathesisOutput(schemaOut, 1)
	if len(sFindings) != 1 || sFindings[0].Endpoint != "POST /api/v1/projects" {
		t.Fatalf("schemathesis parse failed: %+v", sFindings)
	}
}
