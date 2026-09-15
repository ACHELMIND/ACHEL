package compliance

import "time"

type ComplianceConfig struct {
	Framework  string        `json:"framework"`
	Scope      []string      `json:"scope"`
	Timeout    time.Duration `json:"timeout"`
}

type ComplianceResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Score    float64       `json:"score"`
	Findings []string      `json:"findings"`
}

type ComplianceFramework struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Categories  []string `json:"categories"`
	TotalControls int    `json:"total_controls"`
}

type ControlCheck struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

type ComplianceReport struct {
	Framework   string         `json:"framework"`
	Scope       []string       `json:"scope"`
	Score       float64        `json:"score"`
	Passed      int            `json:"passed"`
	Failed      int            `json:"failed"`
	Warning     int            `json:"warning"`
	Controls    []ControlCheck `json:"controls"`
	GeneratedAt time.Time      `json:"generated_at"`
}

type GapAnalysis struct {
	CurrentState string         `json:"current_state"`
	RequiredState string        `json:"required_state"`
	Gaps         []string       `json:"gaps"`
	Recommendations []string    `json:"recommendations"`
	Priority     string         `json:"priority"`
}
