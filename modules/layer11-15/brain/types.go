package brain

import (
	"time"
)

type DecisionConfidence int

const (
	ConfidenceLow DecisionConfidence = iota
	ConfidenceMedium
	ConfidenceHigh
	ConfidenceCertain
)

type ActionType string

const (
	ActionTypeScan       ActionType = "scan"
	ActionTypeExploit    ActionType = "exploit"
	ActionTypePivot      ActionType = "pivot"
	ActionTypePersist    ActionType = "persist"
	ActionTypeExfiltrate ActionType = "exfiltrate"
	ActionTypeDestroy    ActionType = "destroy"
	ActionTypeEvade      ActionType = "evade"
	ActionTypeWait       ActionType = "wait"
	ActionTypeAnalyze    ActionType = "analyze"
)

type BrainConfig struct {
	LearningRate     float64       `json:"learning_rate"`
	ExplorationRate  float64       `json:"exploration_rate"`
	DecisionThreshold float64      `json:"decision_threshold"`
	MaxHistory       int           `json:"max_history"`
	AdaptiveTiming   bool          `json:"adaptive_timing"`
	MinDelay         time.Duration `json:"min_delay"`
	MaxDelay         time.Duration `json:"max_delay"`
}

func DefaultBrainConfig() *BrainConfig {
	return &BrainConfig{
		LearningRate:      0.1,
		ExplorationRate:   0.2,
		DecisionThreshold: 0.6,
		MaxHistory:        1000,
		AdaptiveTiming:    true,
		MinDelay:          1 * time.Second,
		MaxDelay:          30 * time.Second,
	}
}

type EnvironmentState struct {
	HostCount     int               `json:"host_count"`
	AgentCount    int               `json:"agent_count"`
	NetworkHealth float64           `json:"network_health"`
	ThreatLevel   float64           `json:"threat_level"`
	LastAction    string            `json:"last_action"`
	LastOutcome   string            `json:"last_outcome"`
	Metadata      map[string]string `json:"metadata"`
}

type DecisionContext struct {
	State         *EnvironmentState `json:"state"`
	History       []Outcome         `json:"history"`
	AvailableActions []Action       `json:"available_actions"`
	Constraints   map[string]string `json:"constraints"`
}

type Decision struct {
	Action     Action              `json:"action"`
	Confidence DecisionConfidence  `json:"confidence"`
	Reasoning  string              `json:"reasoning"`
	RiskScore  float64             `json:"risk_score"`
	Metadata   map[string]interface{} `json:"metadata"`
}

type Action struct {
	ID         string            `json:"id"`
	Type       ActionType        `json:"type"`
	Target     string            `json:"target"`
	Params     map[string]interface{} `json:"params"`
	RiskLevel  float64           `json:"risk_level"`
	Priority   int               `json:"priority"`
	Timestamp  time.Time         `json:"timestamp"`
}

type Outcome struct {
	ActionID   string    `json:"action_id"`
	ActionType ActionType `json:"action_type"`
	Success    bool      `json:"success"`
	Impact     float64   `json:"impact"`
	Duration   time.Duration `json:"duration"`
	Timestamp  time.Time `json:"timestamp"`
	Error      string    `json:"error,omitempty"`
}

type RiskScore struct {
	Overall    float64 `json:"overall"`
	Impact     float64 `json:"impact"`
	Likelihood float64 `json:"likelihood"`
	Detection  float64 `json:"detection"`
}

type BehaviorPattern struct {
	ActionType  ActionType  `json:"action_type"`
	SuccessRate float64     `json:"success_rate"`
	AvgImpact   float64     `json:"avg_impact"`
	Count       int         `json:"count"`
	LastUsed    time.Time   `json:"last_used"`
}

type TimingState struct {
	CurrentDelay  time.Duration `json:"current_delay"`
	SuccessRate   float64       `json:"success_rate"`
	LastSleep     time.Time     `json:"last_sleep"`
	SleepCount    int           `json:"sleep_count"`
}
