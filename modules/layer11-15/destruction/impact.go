package destruction

import (
	"sort"
	"time"
)

type ImpactAssessor struct{}

func NewImpactAssessor() *ImpactAssessor {
	return &ImpactAssessor{}
}

func (ia *ImpactAssessor) CalculateBlastRadius(target string) (*BlastRadius, error) {
	radius := &BlastRadius{
		Target:           target,
		PrimaryDamage:    DamageLevelHigh,
		CollateralDamage: DamageLevelMedium,
		AffectedSystems:  []string{target},
		AffectedData:     []string{"user_data", "config"},
		RecoveryTime:     24 * time.Hour,
		EscalationPath:   []string{"recon", "exploit", "pivot", "destroy"},
		Metadata:         make(map[string]string),
	}

	switch target {
	case "database", "db":
		radius.PrimaryDamage = DamageLevelCritical
		radius.CollateralDamage = DamageLevelHigh
		radius.AffectedData = append(radius.AffectedData, "database", "backups", "logs")
		radius.RecoveryTime = 72 * time.Hour
	case "filesystem", "files":
		radius.PrimaryDamage = DamageLevelHigh
		radius.CollateralDamage = DamageLevelMedium
		radius.AffectedData = append(radius.AffectedData, "documents", "configs", "secrets")
		radius.RecoveryTime = 48 * time.Hour
	case "disk", "volume":
		radius.PrimaryDamage = DamageLevelCritical
		radius.CollateralDamage = DamageLevelCritical
		radius.AffectedData = append(radius.AffectedData, "all_data", "os", "boot")
		radius.RecoveryTime = 168 * time.Hour
	case "system":
		radius.PrimaryDamage = DamageLevelCritical
		radius.CollateralDamage = DamageLevelCritical
		radius.AffectedSystems = append(radius.AffectedSystems, "network", "dependencies")
		radius.RecoveryTime = 336 * time.Hour
	}

	return radius, nil
}

func (ia *ImpactAssessor) EstimateRecoveryTime(damage DamageLevel) time.Duration {
	switch damage {
	case DamageLevelNone:
		return 0
	case DamageLevelLow:
		return 1 * time.Hour
	case DamageLevelMedium:
		return 12 * time.Hour
	case DamageLevelHigh:
		return 48 * time.Hour
	case DamageLevelCritical:
		return 168 * time.Hour
	default:
		return 24 * time.Hour
	}
}

func (ia *ImpactAssessor) ScoreP0P1(findings []Finding) []ScoredFinding {
	scored := make([]ScoredFinding, 0, len(findings))

	for _, f := range findings {
		sf := ScoredFinding{
			Finding: &f,
			Score:   ia.calculateScore(f),
		}

		switch {
		case sf.Score >= 0.9:
			sf.Priority = 0
			sf.RiskLevel = DamageLevelCritical
		case sf.Score >= 0.7:
			sf.Priority = 0
			sf.RiskLevel = DamageLevelHigh
		case sf.Score >= 0.5:
			sf.Priority = 1
			sf.RiskLevel = DamageLevelMedium
		default:
			sf.Priority = 2
			sf.RiskLevel = DamageLevelLow
		}

		scored = append(scored, sf)
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Score > scored[j].Score
	})

	return scored
}

func (ia *ImpactAssessor) calculateScore(f Finding) float64 {
	score := 0.0

	switch f.Severity {
	case 0:
		score = 0.2
	case 1:
		score = 0.4
	case 2:
		score = 0.7
	case 3:
		score = 0.95
	}

	return score
}
