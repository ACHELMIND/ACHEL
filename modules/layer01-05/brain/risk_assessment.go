package brain

import (
	"sync"
	"time"
)

type RiskAssessment struct {
	mu        sync.RWMutex
	profiles  map[string]*RiskProfile
}

type RiskProfile struct {
	Target      string
	Level       float64
	LastUpdated time.Time
	Factors     []RiskFactor
}

type RiskFactor struct {
	Name     string
	Weight   float64
	Score    float64
}

func NewRiskAssessment() *RiskAssessment {
	return &RiskAssessment{
		profiles: make(map[string]*RiskProfile),
	}
}

func (r *RiskAssessment) Assess(target string, factors []RiskFactor) float64 {
	totalScore := 0.0
	totalWeight := 0.0

	for _, f := range factors {
		totalScore += f.Weight * f.Score
		totalWeight += f.Weight
	}

	if totalWeight == 0 {
		return 0
	}

	riskScore := totalScore / totalWeight

	r.mu.Lock()
	r.profiles[target] = &RiskProfile{
		Target:      target,
		Level:       riskScore,
		LastUpdated: time.Now(),
		Factors:     factors,
	}
	r.mu.Unlock()

	return riskScore
}

func (r *RiskAssessment) GetRiskLevel(target string) float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if profile, exists := r.profiles[target]; exists {
		return profile.Level
	}
	return 0
}

func (r *RiskAssessment) ClassifyRisk(score float64) string {
	if score < 30 {
		return "LOW"
	} else if score < 60 {
		return "MEDIUM"
	} else if score < 80 {
		return "HIGH"
	}
	return "CRITICAL"
}

func (r *RiskAssessment) ShouldProceed(target string, threshold float64) bool {
	level := r.GetRiskLevel(target)
	return level < threshold
}
