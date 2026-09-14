package evasion

import (
	"fmt"
	"time"
)

type EvasionCategory string

const (
	CategorySyscall      EvasionCategory = "syscall"
	CategoryAntiAnalysis EvasionCategory = "anti_analysis"
	CategoryInjection    EvasionCategory = "injection"
	CategoryCleanup      EvasionCategory = "cleanup"
	CategoryNetEvasion   EvasionCategory = "network_evasion"
)

type DetectionType string

const (
	DetectionDebugger  DetectionType = "debugger"
	DetectionVM        DetectionType = "virtual_machine"
	DetectionSandbox   DetectionType = "sandbox"
	DetectionHook      DetectionType = "hook"
	DetectionAnalysis  DetectionType = "analysis"
)

type DetectionResult struct {
	Type      DetectionType `json:"type"`
	Detected  bool          `json:"detected"`
	Method    string        `json:"method"`
	Details   string        `json:"details"`
	RiskScore float64       `json:"risk_score"`
	Timestamp time.Time     `json:"timestamp"`
}

type EvasionConfig struct {
	PrimaryMethod   string
	FallbackMethods []string
	StealthLevel    int
	Timeout         time.Duration
	Randomize       bool
}

type SyscallStub struct {
	SSN        uint16
	Module     string
	Function   string
	Address    uintptr
	Trampoline uintptr
}

type InjectionConfig struct {
	TargetPID   int
	TargetPath  string
	Payload     []byte
	Method      string
	StealthMode bool
}

type CleanupConfig struct {
	ClearEventLogs     bool
	ClearPrefetch      bool
	ClearShellHistory  bool
	ClearForensics     bool
	MaxAge             time.Duration
	DryRun             bool
}

type NetworkEvasionConfig struct {
	IPPool            []string
	UserAgents        []string
	TLSFingerprints   []string
	DNSEncodingType   string
	TrafficMorphing   bool
	JitterPercent     float64
}

type SyscallMethod interface {
	Name() string
	Execute(stub *SyscallStub, args ...uintptr) (uintptr, error)
	Description() string
	Category() EvasionCategory
}

type InjectionMethod interface {
	Name() string
	Execute(config *InjectionConfig) error
	Description() string
	Category() EvasionCategory
	Validate(config *InjectionConfig) error
}

type AntiDetector interface {
	Name() string
	Detect() DetectionResult
	Category() DetectionType
}

type EvasionReport struct {
	Module      string             `json:"module"`
	Results     []DetectionResult  `json:"results"`
	Timestamp   time.Time          `json:"timestamp"`
	RiskScore   float64            `json:"risk_score"`
	StealthMode bool               `json:"stealth_mode"`
}

func (r *EvasionReport) AddResult(result DetectionResult) {
	r.Results = append(r.Results, result)
	if result.Detected && result.RiskScore > r.RiskScore {
		r.RiskScore = result.RiskScore
	}
}

func (r *EvasionReport) String() string {
	summary := fmt.Sprintf("Evasion Report [%s]\n", r.Module)
	for _, result := range r.Results {
		status := "CLEAN"
		if result.Detected {
			status = "DETECTED"
		}
		summary += fmt.Sprintf("  [%s] %s: %s (risk: %.2f)\n", status, result.Method, result.Details, result.RiskScore)
	}
	summary += fmt.Sprintf("  Overall Risk: %.2f\n", r.RiskScore)
	return summary
}

func NewDefaultCleanupConfig() *CleanupConfig {
	return &CleanupConfig{
		ClearEventLogs:    true,
		ClearPrefetch:     true,
		ClearShellHistory: true,
		ClearForensics:    true,
		MaxAge:            24 * time.Hour,
	}
}

func NewDefaultNetworkConfig() *NetworkEvasionConfig {
	return &NetworkEvasionConfig{
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		},
		TLSFingerprints: []string{
			"chrome_120",
			"firefox_121",
			"safari_17",
		},
		DNSEncodingType: "hex",
		TrafficMorphing: true,
		JitterPercent:   0.25,
	}
}
