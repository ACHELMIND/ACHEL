package brain

import (
	"math"
	"sync"
	"time"
)

type AutonomousDecision struct {
	mu          sync.RWMutex
	riskLevel   float64
	history     []Decision
	thresholds  Thresholds
}

type Decision struct {
	ID        string
	Action    string
	Risk      float64
	Success   bool
	Timestamp time.Time
}

type Thresholds struct {
	AutoExecute float64
	RequestApproval float64
	BlockAlert float64
}

func NewAutonomousDecision() *AutonomousDecision {
	return &AutonomousDecision{
		riskLevel: 0.0,
		history: make([]Decision, 0),
		thresholds: Thresholds{
			AutoExecute: 30,
			RequestApproval: 70,
			BlockAlert: 70,
		},
	}
}

func (a *AutonomousDecision) EvaluateAction(action string, context map[string]interface{}) (string, float64) {
	riskScore := a.calculateRisk(action, context)

	if riskScore < a.thresholds.AutoExecute {
		return "AUTO_EXECUTE", riskScore
	} else if riskScore < a.thresholds.RequestApproval {
		return "REQUEST_APPROVAL", riskScore
	}
	return "BLOCK_ALERT", riskScore
}

func (a *AutonomousDecision) calculateRisk(action string, context map[string]interface{}) float64 {
	baseRisk := 0.0

	switch action {
	case "recon":
		baseRisk = 10
	case "exploit":
		baseRisk = 50
	case "lateral":
		baseRisk = 40
	case "exfil":
		baseRisk = 60
	case "destruct":
		baseRisk = 90
	default:
		baseRisk = 30
	}

	if destructive, ok := context["destructive"].(bool); ok && destructive {
		baseRisk = math.Min(baseRisk*1.5, 100)
	}

	return baseRisk
}

func (a *AutonomousDecision) RecordDecision(decision Decision) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.history = append(a.history, decision)
}

func (a *AutonomousDecision) GetHistory() []Decision {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.history
}
