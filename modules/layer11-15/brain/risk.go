package brain

import (
	"math"
)

type RiskAssessor struct{}

func NewRiskAssessor() *RiskAssessor {
	return &RiskAssessor{}
}

func (ra *RiskAssessor) AssessRisk(action *Action) *RiskScore {
	if action == nil {
		return &RiskScore{Overall: 1.0}
	}

	impact := ra.CalculateImpact(action.Target)
	likelihood := ra.CalculateLikelihood(action)
	detection := ra.estimateDetection(action)

	overall := (impact*0.4 + likelihood*0.3 + detection*0.3)
	overall = math.Min(1.0, math.Max(0.0, overall))

	return &RiskScore{
		Overall:    overall,
		Impact:     impact,
		Likelihood: likelihood,
		Detection:  detection,
	}
}

func (ra *RiskAssessor) CalculateImpact(target string) float64 {
	switch target {
	case "domain_controller", "dc":
		return 0.95
	case "database", "db":
		return 0.9
	case "fileserver", "files":
		return 0.7
	case "workstation":
		return 0.5
	case "network":
		return 0.8
	case "self":
		return 0.1
	default:
		return 0.5
	}
}

func (ra *RiskAssessor) CalculateLikelihood(action *Action) float64 {
	if action == nil {
		return 1.0
	}

	switch action.Type {
	case ActionTypeScan:
		return 0.3
	case ActionTypeExploit:
		return 0.7
	case ActionTypePivot:
		return 0.5
	case ActionTypePersist:
		return 0.6
	case ActionTypeExfiltrate:
		return 0.8
	case ActionTypeDestroy:
		return 0.95
	case ActionTypeEvade:
		return 0.2
	case ActionTypeWait:
		return 0.05
	default:
		return 0.5
	}
}

func (ra *RiskAssessor) estimateDetection(action *Action) float64 {
	if action == nil {
		return 1.0
	}

	switch action.Type {
	case ActionTypeScan:
		return 0.4
	case ActionTypeExploit:
		return 0.7
	case ActionTypePivot:
		return 0.5
	case ActionTypePersist:
		return 0.6
	case ActionTypeExfiltrate:
		return 0.8
	case ActionTypeDestroy:
		return 0.9
	case ActionTypeEvade:
		return 0.15
	case ActionTypeWait:
		return 0.02
	default:
		return 0.5
	}
}
