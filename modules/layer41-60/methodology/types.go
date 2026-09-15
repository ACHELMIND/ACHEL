package methodology

import "time"

type MethodologyConfig struct {
	Scope    []string      `json:"scope"`
	Timeout  time.Duration `json:"timeout"`
	Phase    string        `json:"phase"`
}

type MethodologyResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Findings []string      `json:"findings"`
	Score    float64       `json:"score"`
}

type OWASPCategory struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tests       []string `json:"tests"`
}

type TestPhase struct {
	Name        string         `json:"name"`
	Status      string         `json:"status"`
	Tests       []TestItem     `json:"tests"`
	StartTime   time.Time      `json:"start_time"`
	EndTime     time.Time      `json:"end_time"`
}

type TestItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type ReconResult struct {
	Domains    []string `json:"domains"`
	IPs        []string `json:"ips"`
	Ports      []int    `json:"ports"`
	Services   []string `json:"services"`
	TechStack  []string `json:"tech_stack"`
}

type DiscoveryResult struct {
	Endpoints  []string `json:"endpoints"`
	Parameters []string `json:"parameters"`
	Files      []string `json:"files"`
	Subdomains []string `json:"subdomains"`
}

type ExploitationResult struct {
	Vulns      []string `json:"vulns"`
	PoCs       []string `json:"pocs"`
	Impact     string   `json:"impact"`
}

type ReportingResult struct {
	Summary    string   `json:"summary"`
	Findings   []string `json:"findings"`
	Remediation []string `json:"remediation"`
	RiskLevel  string   `json:"risk_level"`
}
