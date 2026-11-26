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
	CategorySAST         FindingCategory = "sast"
	CategorySecret       FindingCategory = "secret"
	CategoryIaC          FindingCategory = "iac"
	CategorySCA          FindingCategory = "sca"
	CategoryDAST         FindingCategory = "dast"
	CategoryPenTest      FindingCategory = "pentest"
	CategoryCycle        FindingCategory = "cycle"
	CategoryMalware      FindingCategory = "malware"
	CategorySupplyChain  FindingCategory = "supply-chain"
	CategoryResourceLeak FindingCategory = "resource-leak"
	CategoryArchitecture FindingCategory = "architecture"
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

type RateLimitCapability struct {
	Enabled         bool   `json:"enabled"`
	Path            string `json:"path,omitempty"`
	LoginBurstCount int    `json:"loginBurstCount,omitempty"`
}

type GraphQLCapability struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path,omitempty"`
}

type UploadCapability struct {
	Enabled   bool   `json:"enabled"`
	Path      string `json:"path"`
	FieldName string `json:"fieldName,omitempty"`
}

type DiagnosticsCapability struct {
	Enabled         bool   `json:"enabled"`
	PprofBaseURL    string `json:"pprofBaseUrl,omitempty"`
	RuntimeStatsURL string `json:"runtimeStatsUrl,omitempty"`
	GCTriggerURL    string `json:"gcTriggerUrl,omitempty"`
}

type LayerDefinition struct {
	Name         string   `json:"name"`
	PathPrefixes []string `json:"pathPrefixes"`
}

type LayerFlowRule struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason,omitempty"`
}

type ArchitectureRules struct {
	Layers                      []LayerDefinition `json:"layers,omitempty"`
	ForbiddenFlows              []LayerFlowRule   `json:"forbiddenFlows,omitempty"`
	PublicRoutes                []string          `json:"publicRoutes,omitempty"`
	RequireAuthOnNonPublic      bool              `json:"requireAuthOnNonPublic,omitempty"`
	RequireRateLimitOnNonPublic bool              `json:"requireRateLimitOnNonPublic,omitempty"`
	RequireValidationOnMutating bool              `json:"requireValidationOnMutating,omitempty"`
}

type ManifestCapabilities struct {
	Health      EndpointSpec           `json:"health"`
	Auth        *AuthCapabilities      `json:"auth,omitempty"`
	CRUD        *CRUDCapabilities      `json:"crud,omitempty"`
	RBAC        *RBACCapabilities      `json:"rbac,omitempty"`
	SSRFTest    *SSRFTestCapability    `json:"ssrfTest,omitempty"`
	WebSockets  *WebSocketCapability   `json:"websockets,omitempty"`
	RateLimit   *RateLimitCapability   `json:"rateLimit,omitempty"`
	GraphQL     *GraphQLCapability     `json:"graphql,omitempty"`
	Upload      *UploadCapability      `json:"upload,omitempty"`
	Diagnostics *DiagnosticsCapability `json:"diagnostics,omitempty"`
}

type BoilerplateManifest struct {
	Name         string               `json:"name"`
	Language     BoilerplateLanguage  `json:"language"`
	OpenAPIURL   string               `json:"openapiUrl,omitempty"`
	Capabilities ManifestCapabilities `json:"capabilities"`
	Architecture *ArchitectureRules   `json:"architecture,omitempty"`
}

type CodeFlowStep struct {
	FilePath string `json:"filePath"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Message  string `json:"message,omitempty"`
	Kind     string `json:"kind,omitempty"` // "source" | "propagator" | "sanitizer" | "sink"
}

type SecurityFinding struct {
	ID          string           `json:"id"`
	Category    FindingCategory  `json:"category"`
	Tool        string           `json:"tool"`
	Severity    Severity         `json:"severity"`
	Title       string           `json:"title"`
	Description string           `json:"description,omitempty"`
	FilePath    string           `json:"filePath,omitempty"`
	Line        int              `json:"line,omitempty"`
	Endpoint    string           `json:"endpoint,omitempty"`
	CWE         string           `json:"cwe,omitempty"`
	CVE         string           `json:"cve,omitempty"`
	PackageName string           `json:"packageName,omitempty"`
	Reachable   *bool            `json:"reachable,omitempty"`
	KEV         bool             `json:"kev,omitempty"`
	EPSS        float64          `json:"epss,omitempty"`
	CodeFlows   [][]CodeFlowStep `json:"codeFlows,omitempty"`
}

type GraphNode struct {
	ID              string   `json:"id"`
	Label           string   `json:"label"`
	Type            string   `json:"type"`
	Version         string   `json:"version,omitempty"`
	Sinks           []string `json:"sinks,omitempty"`
	CVEs            []string `json:"cves,omitempty"`
	Findings        []string `json:"findings,omitempty"`
	ExternalImports []string `json:"externalImports,omitempty"`
	Layer           string   `json:"layer,omitempty"`
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

type LayerViolation struct {
	ID        string   `json:"id"`
	FromFile  string   `json:"fromFile"`
	ToFile    string   `json:"toFile"`
	FromLayer string   `json:"fromLayer"`
	ToLayer   string   `json:"toLayer"`
	Reason    string   `json:"reason,omitempty"`
	Severity  Severity `json:"severity"`
}

type RouteGuardFinding struct {
	ID            string   `json:"id"`
	Method        string   `json:"method"`
	Path          string   `json:"path"`
	FilePath      string   `json:"filePath"`
	Line          int      `json:"line,omitempty"`
	Kind          string   `json:"kind"` // "unprotected-route" | "shadow-route"
	MissingGuards []string `json:"missingGuards,omitempty"`
	Severity      Severity `json:"severity"`
}

type DependencyGraph struct {
	Nodes           []GraphNode         `json:"nodes"`
	Edges           []GraphEdge         `json:"edges"`
	Cycles          []CycleFinding      `json:"cycles"`
	LayerViolations []LayerViolation    `json:"layerViolations,omitempty"`
	RouteFindings   []RouteGuardFinding `json:"routeFindings,omitempty"`
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

type RuntimeTelemetrySnapshot struct {
	Goroutines         int   `json:"goroutines,omitempty"`
	HeapInUseBytes     int64 `json:"heapInUseBytes,omitempty"`
	HeapObjects        int64 `json:"heapObjects,omitempty"`
	V8UsedHeapBytes    int64 `json:"v8UsedHeapBytes,omitempty"`
	ActiveHandles      int   `json:"activeHandles,omitempty"`
	PyTracemallocBytes int64 `json:"pyTracemallocBytes,omitempty"`
	PyAsyncTasks       int   `json:"pyAsyncTasks,omitempty"`
	BeamProcessCount   int   `json:"beamProcessCount,omitempty"`
	BeamAtomBytes      int64 `json:"beamAtomBytes,omitempty"`
	BeamBinaryBytes    int64 `json:"beamBinaryBytes,omitempty"`
	BeamETSBytes       int64 `json:"beamEtsBytes,omitempty"`
}

type MemorySample struct {
	TimestampMs      int64   `json:"timestampMs"`
	RSSBytes         int64   `json:"rssBytes"`
	WorkingSetBytes  int64   `json:"workingSetBytes,omitempty"`
	CPUPercent       float64 `json:"cpuPercent"`
	OpenFDs          int     `json:"openFds,omitempty"`
	CloseWaitSockets int     `json:"closeWaitSockets,omitempty"`
}

type MemoryLeakAnalysis struct {
	InitialRSSBytes         int64                     `json:"initialRssBytes"`
	FinalRSSBytes           int64                     `json:"finalRssBytes"`
	PeakRSSBytes            int64                     `json:"peakRssBytes"`
	DriftPercent            float64                   `json:"driftPercent"`
	LeakDetected            bool                      `json:"leakDetected"`
	PostWarmupBaselineBytes int64                     `json:"postWarmupBaselineBytes,omitempty"`
	PostCooldownRSSBytes    int64                     `json:"postCooldownRssBytes,omitempty"`
	RetainedDriftPercent    float64                   `json:"retainedDriftPercent,omitempty"`
	SlopeBytesPerSec        float64                   `json:"slopeBytesPerSec,omitempty"`
	SlopeBytesPerReq        float64                   `json:"slopeBytesPerReq,omitempty"`
	SlopeR2                 float64                   `json:"slopeR2,omitempty"`
	FDDelta                 int                       `json:"fdDelta,omitempty"`
	CloseWaitDelta          int                       `json:"closeWaitDelta,omitempty"`
	GoroutineDelta          int                       `json:"goroutineDelta,omitempty"`
	HeapInUseDeltaBytes     int64                     `json:"heapInUseDeltaBytes,omitempty"`
	BeamAtomDeltaBytes      int64                     `json:"beamAtomDeltaBytes,omitempty"`
	PreSoakDiag             *RuntimeTelemetrySnapshot `json:"preSoakDiag,omitempty"`
	PostCooldownDiag        *RuntimeTelemetrySnapshot `json:"postCooldownDiag,omitempty"`
	Samples                 []MemorySample            `json:"samples,omitempty"`
}

type EgressViolation struct {
	TimestampMs int64  `json:"timestampMs"`
	RemoteAddr  string `json:"remoteAddr"`
	Process     string `json:"process,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type SecurityPolicy struct {
	FailOnAnySourceCycle          bool    `json:"failOnAnySourceCycle"`
	FailOnAnyPackageCycle         bool    `json:"failOnAnyPackageCycle"`
	FailOnLayerViolation          bool    `json:"failOnLayerViolation"`
	FailOnUnprotectedRoute        bool    `json:"failOnUnprotectedRoute"`
	FailOnShadowRoute             bool    `json:"failOnShadowRoute"`
	MaxCriticalFindings           int     `json:"maxCriticalFindings"`
	MaxHighFindings               int     `json:"maxHighFindings"`
	MaxMalwareFindings            int     `json:"maxMalwareFindings"`
	MaxPenTestFailures            int     `json:"maxPenTestFailures"`
	RequireLoadTestPass           bool    `json:"requireLoadTestPass"`
	RequireMemoryOnSoak           bool    `json:"requireMemoryOnSoak"`
	MaxMemoryDriftPercent         float64 `json:"maxMemoryDriftPercent"`
	MaxRetainedMemoryDriftPercent float64 `json:"maxRetainedMemoryDriftPercent"`
	MaxMemorySlopeBytesPerReq     float64 `json:"maxMemorySlopeBytesPerReq"`
	MaxFDGrowth                   int     `json:"maxFdGrowth"`
	MaxGoroutineGrowth            int     `json:"maxGoroutineGrowth"`
	MaxEgressViolations           int     `json:"maxEgressViolations"`
}

type SecurityWaiver struct {
	FindingID     string `json:"findingId,omitempty"`
	RuleOrCVE     string `json:"ruleOrCve,omitempty"`
	Justification string `json:"justification"`
	ApprovedBy    string `json:"approvedBy"`
	ExpiresAt     string `json:"expiresAt"`
}

type WaiverFile struct {
	Waivers []SecurityWaiver `json:"waivers"`
}

type PolicyEvaluationResult struct {
	Passed     bool     `json:"passed"`
	Violations []string `json:"violations"`
}

type ConformanceScorecard struct {
	TargetName       string               `json:"targetName"`
	Language         BoilerplateLanguage  `json:"language"`
	Timestamp        string               `json:"timestamp"`
	Findings         []SecurityFinding    `json:"findings"`
	SourceGraph      DependencyGraph      `json:"sourceGraph"`
	PackageGraph     DependencyGraph      `json:"packageGraph"`
	PenTestResults   []PenTestCheckResult `json:"penTestResults"`
	LoadTest         *LoadTestSummary     `json:"loadTest,omitempty"`
	MemoryAnalysis   *MemoryLeakAnalysis  `json:"memoryAnalysis,omitempty"`
	EgressViolations []EgressViolation    `json:"egressViolations,omitempty"`
}
