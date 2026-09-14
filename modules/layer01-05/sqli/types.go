package sqli

import (
	"net/http"
	"sync"
	"time"
)

type DBMSType string

const (
	DBMSMySQL     DBMSType = "mysql"
	DBMSPostgres  DBMSType = "postgresql"
	DBMSMSSQL     DBMSType = "mssql"
	DBMSOracle    DBMSType = "oracle"
	DBMSSQLite    DBMSType = "sqlite"
	DBMSUnknown   DBMSType = "unknown"
)

type InjectionType string

const (
	InjectionBooleanBlind InjectionType = "boolean_blind"
	InjectionTimeBased    InjectionType = "time_based"
	InjectionErrorBased   InjectionType = "error_based"
	InjectionUnionBased   InjectionType = "union_based"
	InjectionStacked      InjectionType = "stacked"
	InjectionOOBDNS      InjectionType = "oob_dns"
	InjectionOOBHTTP     InjectionType = "oob_http"
	InjectionOOBICMP     InjectionType = "oob_icmp"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type TechniqueStatus string

const (
	TechniqueStatusPending   TechniqueStatus = "pending"
	TechniqueStatusRunning   TechniqueStatus = "running"
	TechniqueStatusCompleted TechniqueStatus = "completed"
	TechniqueStatusFailed    TechniqueStatus = "failed"
	TechniqueStatusSkipped   TechniqueStatus = "skipped"
)

type ParameterLocation string

const (
	ParamQuery    ParameterLocation = "query"
	ParamBody     ParameterLocation = "body"
	ParamCookie   ParameterLocation = "cookie"
	ParamHeader   ParameterLocation = "header"
	ParamJSON     ParameterLocation = "json"
	ParamXML      ParameterLocation = "xml"
	ParamGraphQL  ParameterLocation = "graphql"
	ParamMultipart ParameterLocation = "multipart"
)

type SQLiConfig struct {
	Target          string
	Timeout         time.Duration
	MaxConcurrency  int
	Retries         int
	Techniques      []InjectionType
	DBMS            DBMSType
	Level           int
	Risk            int
	 tamper         bool
	UseWAFBypass    bool
	Verbose         bool
	ProxyURL        string
	CustomHeaders   map[string]string
	Cookies         map[string]string
	Params          []string
	HTTPClient      *http.Client
}

func DefaultConfig() *SQLiConfig {
	return &SQLiConfig{
		Timeout:        30 * time.Second,
		MaxConcurrency: 5,
		Retries:        2,
		Techniques: []InjectionType{
			InjectionBooleanBlind,
			InjectionTimeBased,
			InjectionErrorBased,
			InjectionUnionBased,
			InjectionStacked,
			InjectionOOBDNS,
			InjectionOOBHTTP,
			InjectionOOBICMP,
		},
		DBMS:       DBMSUnknown,
		Level:      1,
		Risk:       1,
		UseWAFBypass: true,
		Verbose:    false,
	}
}

type Technique struct {
	Name        string         `json:"name"`
	Type        InjectionType  `json:"type"`
	Priority    int            `json:"priority"`
	Status      TechniqueStatus `json:"status"`
	Error       string         `json:"error,omitempty"`
	Duration    time.Duration  `json:"duration"`
	Result      *InjectionResult `json:"result,omitempty"`
}

type InjectionPoint struct {
	URL          string            `json:"url"`
	Parameter    string            `json:"parameter"`
	Location     ParameterLocation `json:"location"`
	InjectionType InjectionType    `json:"injection_type"`
	DBMS         DBMSType          `json:"dbms"`
	Payload      string            `json:"payload"`
	Evidence     string            `json:"evidence"`
	Confidence   float64           `json:"confidence"`
	Severity     Severity          `json:"severity"`
	Details      map[string]string `json:"details,omitempty"`
}

type InjectionResult struct {
	Found       bool              `json:"found"`
	Type        InjectionType     `json:"type"`
	DBMS        DBMSType          `json:"dbms"`
	Payload     string            `json:"payload"`
	Evidence    string            `json:"evidence"`
	Confidence  float64           `json:"confidence"`
	Severity    Severity          `json:"severity"`
	Response    *HTTPResponse     `json:"response,omitempty"`
	TimingDelta time.Duration     `json:"timing_delta,omitempty"`
	ErrorMsg    string            `json:"error_msg,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
}

type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Length     int               `json:"length"`
	Timing     time.Duration     `json:"timing"`
}

type ExploitResult struct {
	Success     bool              `json:"success"`
	InjectionPt *InjectionPoint   `json:"injection_point"`
	DBMS        DBMSType          `json:"dbms"`
	Version     string            `json:"version,omitempty"`
	Database    string            `json:"database,omitempty"`
	User        string            `json:"user,omitempty"`
	Hostname    string            `json:"hostname,omitempty"`
	Privileges  []string          `json:"privileges,omitempty"`
	Databases   []string          `json:"databases,omitempty"`
	Tables      []string          `json:"tables,omitempty"`
	Columns     []string          `json:"columns,omitempty"`
	Data        map[string]string `json:"data,omitempty"`
	RawOutput   string            `json:"raw_output,omitempty"`
	Error       string            `json:"error,omitempty"`
}

type ScanResult struct {
	Target          string            `json:"target"`
	Vulnerable      bool              `json:"vulnerable"`
	InjectionPoints []*InjectionPoint `json:"injection_points,omitempty"`
	Techniques      []*Technique      `json:"techniques,omitempty"`
	DBMS            DBMSType          `json:"dbms"`
	StartTime       time.Time         `json:"start_time"`
	EndTime         time.Time         `json:"end_time"`
	Duration        time.Duration     `json:"duration"`
	Error           string            `json:"error,omitempty"`
	mu              sync.Mutex        `json:"-"`
}

func (s *ScanResult) AddInjectionPoint(pt *InjectionPoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.InjectionPoints = append(s.InjectionPoints, pt)
	s.Vulnerable = true
}

func (s *ScanResult) AddTechnique(t *Technique) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Techniques = append(s.Techniques, t)
}

type Detector interface {
	Detect(url string, params []string) (*InjectionResult, error)
	Name() string
	Type() InjectionType
}

type WAFBypass interface {
	Bypass(payload string) string
	Name() string
}
