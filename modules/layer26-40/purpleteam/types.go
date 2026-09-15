package purpleteam

import "time"

type DetectionTest struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`
	Technique   string `json:"technique"`
	TechniqueID string `json:"technique_id"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	ExpectedAlert bool `json:"expected_alert"`
	ActualAlert   bool `json:"actual_alert"`
	Detected      bool `json:"detected"`
	LatencyMs     int  `json:"latency_ms"`
	Details       string `json:"details"`
}

type PurpleTeamConfig struct {
	Environment    string
	TargetRange    string
	TestSuite      []string
	StartTime      time.Time
	EndTime        time.Time
	AlertEndpoint  string
	LogEndpoint    string
	MITREVersion   string
	Techniques     []string
	ExcludeTechs   []string
}

type PurpleResult struct {
	ID             string           `json:"id"`
	Environment    string           `json:"environment"`
	TotalTests     int              `json:"total_tests"`
	Passed         int              `json:"passed"`
	Failed         int              `json:"failed"`
	Skipped        int              `json:"skipped"`
	DetectionRate  float64          `json:"detection_rate"`
	Tests          []DetectionTest  `json:"tests"`
	Coverage       []MITREMapping   `json:"coverage"`
	Recommendations []string        `json:"recommendations"`
	Timestamp      time.Time        `json:"timestamp"`
}

type MITREMapping struct {
	TacticID       string   `json:"tactic_id"`
	TacticName     string   `json:"tactic_name"`
	TechniqueIDs   []string `json:"technique_ids"`
	TechniqueNames []string `json:"technique_names"`
	DetectedCount  int      `json:"detected_count"`
	TotalCount     int      `json:"total_count"`
	CoveragePct    float64  `json:"coverage_pct"`
}

type AlertValidation struct {
	AlertID     string `json:"alert_id"`
	RuleName    string `json:"rule_name"`
	Expected    bool   `json:"expected"`
	Received    bool   `json:"received"`
	Valid       bool   `json:"valid"`
	FalsePositive bool `json:"false_positive"`
	LatencyMs   int    `json:"latency_ms"`
}

type DetectionRule struct {
	Name        string   `json:"name"`
	ID          string   `json:"id"`
	MITRETechs  []string `json:"mitre_techniques"`
	Severity    string   `json:"severity"`
	Enabled     bool     `json:"enabled"`
	FalsePosRate float64 `json:"false_pos_rate"`
}
