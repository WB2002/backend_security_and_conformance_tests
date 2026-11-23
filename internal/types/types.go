package types

type BoilerplateLanguage string

const (
	LangTypeScript BoilerplateLanguage = "typescript"
	LangJavaScript BoilerplateLanguage = "javascript"
	LangGo         BoilerplateLanguage = "go"
	LangPython     BoilerplateLanguage = "python"
	LangElixir     BoilerplateLanguage = "elixir"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type FindingCategory string

const (
	CategorySAST    FindingCategory = "sast"
	CategorySecret  FindingCategory = "secret"
	CategoryIaC     FindingCategory = "iac"
	CategorySCA     FindingCategory = "sca"
	CategoryDAST    FindingCategory = "dast"
	CategoryPenTest FindingCategory = "pentest"
	CategoryCycle   FindingCategory = "cycle"
)

type EndpointSpec struct {
	Method        string         `json:"method,omitempty"`
	Path          string         `json:"path"`
	EmailField    string         `json:"emailField,omitempty"`
	PasswordField string         `json:"passwordField,omitempty"`
	TokenPath     string         `json:"tokenPath,omitempty"`
	RefreshPath   string         `json:"refreshPath,omitempty"`
	UserIDPath    string         `json:"userIdPath,omitempty"`
	ExtraFields   map[string]any `json:"extraFields,omitempty"`
}

type AuthCapabilities struct {
	Register EndpointSpec  `json:"register"`
	Login    EndpointSpec  `json:"login"`
	Me       EndpointSpec  `json:"me"`
	Refresh  *EndpointSpec `json:"refresh,omitempty"`
}

type CRUDCapabilities struct {
	CollectionPath   string         `json:"collectionPath"`
	ItemPath         string         `json:"itemPath"`
	IDPath           string         `json:"idPath,omitempty"`
	SampleCreateBody map[string]any `json:"sampleCreateBody,omitempty"`
}

type RBACCapabilities struct {
	AdminPath   string `json:"adminPath"`
	AdminMethod string `json:"adminMethod,omitempty"`
}

type SSRFTestCapability struct {
	Enabled  bool   `json:"enabled"`
	Method   string `json:"method,omitempty"`
	Path     string `json:"path"`
	URLField string `json:"urlField"`
}

type WebSocketCapability struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

type ManifestCapabilities struct {
	Health     EndpointSpec         `json:"health"`
	Auth       *AuthCapabilities    `json:"auth,omitempty"`
	CRUD       *CRUDCapabilities    `json:"crud,omitempty"`
	RBAC       *RBACCapabilities    `json:"rbac,omitempty"`
	SSRFTest   *SSRFTestCapability  `json:"ssrfTest,omitempty"`
	WebSockets *WebSocketCapability `json:"websockets,omitempty"`
}

type BoilerplateManifest struct {
	Name         string               `json:"name"`
	Language     BoilerplateLanguage  `json:"language"`
	OpenAPIURL   string               `json:"openapiUrl,omitempty"`
	Capabilities ManifestCapabilities `json:"capabilities"`
}

type SecurityFinding struct {
	ID          string          `json:"id"`
	Category    FindingCategory `json:"category"`
	Tool        string          `json:"tool"`
	Severity    Severity        `json:"severity"`
	Title       string          `json:"title"`
	Description string          `json:"description,omitempty"`
	FilePath    string          `json:"filePath,omitempty"`
	Line        int             `json:"line,omitempty"`
	Endpoint    string          `json:"endpoint,omitempty"`
	CWE         string          `json:"cwe,omitempty"`
	CVE         string          `json:"cve,omitempty"`
	PackageName string          `json:"packageName,omitempty"`
}

type GraphNode struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`
	Version  string   `json:"version,omitempty"`
	Sinks    []string `json:"sinks,omitempty"`
	CVEs     []string `json:"cves,omitempty"`
	Findings []string `json:"findings,omitempty"`
}

type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type CycleFinding struct {
	ID              string   `json:"id"`
	GraphType       string   `json:"graphType"`
	Nodes           []string `json:"nodes"`
	IsToxic         bool     `json:"isToxic"`
	Severity        Severity `json:"severity"`
	Reasons         []string `json:"reasons,omitempty"`
	RelatedFindings []string `json:"relatedFindings,omitempty"`
}

type DependencyGraph struct {
	Nodes  []GraphNode    `json:"nodes"`
	Edges  []GraphEdge    `json:"edges"`
	Cycles []CycleFinding `json:"cycles"`
}

type PenTestCheckResult struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"` // "passed", "failed", "skipped"
	Severity Severity `json:"severity"`
	Details  string   `json:"details,omitempty"`
	Endpoint string   `json:"endpoint,omitempty"`
}

type LoadTestSummary struct {
	Profile       string  `json:"profile"`
	Passed        bool    `json:"passed"`
	TotalRequests int64   `json:"totalRequests"`
	RPS           float64 `json:"rps"`
	AvgMs         float64 `json:"avgMs"`
	P95Ms         float64 `json:"p95Ms"`
	P99Ms         float64 `json:"p99Ms"`
	ErrorRate     float64 `json:"errorRate"`
}

type MemorySample struct {
	TimestampMs int64   `json:"timestampMs"`
	RSSBytes    int64   `json:"rssBytes"`
	CPUPercent  float64 `json:"cpuPercent"`
}

type MemoryLeakAnalysis struct {
	InitialRSSBytes int64          `json:"initialRssBytes"`
	FinalRSSBytes   int64          `json:"finalRssBytes"`
	PeakRSSBytes    int64          `json:"peakRssBytes"`
	DriftPercent    float64        `json:"driftPercent"`
	LeakDetected    bool           `json:"leakDetected"`
	Samples         []MemorySample `json:"samples,omitempty"`
}

type SecurityPolicy struct {
	FailOnAnySourceCycle   bool    `json:"failOnAnySourceCycle"`
	FailOnAnyPackageCycle  bool    `json:"failOnAnyPackageCycle"`
	MaxCriticalFindings    int     `json:"maxCriticalFindings"`
	MaxHighFindings        int     `json:"maxHighFindings"`
	MaxPenTestFailures     int     `json:"maxPenTestFailures"`
	RequireLoadTestPass    bool    `json:"requireLoadTestPass"`
	MaxMemoryDriftPercent  float64 `json:"maxMemoryDriftPercent"`
}

type PolicyEvaluationResult struct {
	Passed     bool     `json:"passed"`
	Violations []string `json:"violations"`
}

type ConformanceScorecard struct {
	TargetName     string               `json:"targetName"`
	Language       BoilerplateLanguage  `json:"language"`
	Timestamp      string               `json:"timestamp"`
	Findings       []SecurityFinding    `json:"findings"`
	SourceGraph    DependencyGraph      `json:"sourceGraph"`
	PackageGraph   DependencyGraph      `json:"packageGraph"`
	PenTestResults []PenTestCheckResult `json:"penTestResults"`
	LoadTest       *LoadTestSummary     `json:"loadTest,omitempty"`
	MemoryAnalysis *MemoryLeakAnalysis  `json:"memoryAnalysis,omitempty"`
}
