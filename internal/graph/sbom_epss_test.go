package graph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOSVGHSAWithCVEAliasPopulatesCVEAndReceivesEPSS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cve") != "CVE-2025-29927" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-2025-29927","epss":"0.94210"}]}`))
	}))
	defer srv.Close()

	prevURL := epssBaseURL
	epssBaseURL = srv.URL
	t.Cleanup(func() { epssBaseURL = prevURL })

	cdx := []byte(`{
  "components": [
    { "bom-ref": "pkg:npm/next@14.2.0", "name": "next", "version": "14.2.0" }
  ],
  "dependencies": []
}`)
	osv := []byte(`{
  "results": [
    {
      "packages": [
        {
          "package": { "name": "next", "version": "14.2.0", "ecosystem": "npm" },
          "vulnerabilities": [
            {
              "id": "GHSA-f82v-jwr5-mffw",
              "aliases": ["CVE-2025-29927"],
              "summary": "Next.js middleware authorization bypass",
              "database_specific": { "severity": "HIGH" }
            }
          ]
        }
      ]
    }
  ]
}`)

	_, findings, err := ParseCycloneDXSBOMGraph(cdx, osv)
	if err != nil {
		t.Fatalf("ParseCycloneDXSBOMGraph failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CVE != "CVE-2025-29927" {
		t.Fatalf("expected finding.CVE to prefer CVE alias CVE-2025-29927, got %q", findings[0].CVE)
	}

	enriched := EnrichFindingsWithEPSS(context.Background(), findings, true)
	if len(enriched) != 1 || enriched[0].EPSS < 0.94 || enriched[0].EPSS > 0.95 {
		t.Fatalf("expected EPSS ~0.94210 from alias CVE enrichment, got %+v", enriched)
	}
}
