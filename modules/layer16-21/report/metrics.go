package report

import (
	"github.com/angel-platform/angel/pkg/types"
)

type MetricsResult struct {
	Breakdown  SeverityBreakdown `json:"breakdown"`
	Total      int               `json:"total"`
	RiskScore  float64           `json:"risk_score"`
	Categories map[string]int    `json:"categories"`
}

func CalculateMetrics(findings []Finding) *MetricsResult {
	m := &MetricsResult{
		Total:      len(findings),
		Categories: make(map[string]int),
	}

	for _, f := range findings {
		switch f.Severity {
		case types.SeverityCritical:
			m.Breakdown.Critical++
		case types.SeverityHigh:
			m.Breakdown.High++
		case types.SeverityMedium:
			m.Breakdown.Medium++
		case types.SeverityLow:
			m.Breakdown.Low++
		}
		m.Categories[f.Category]++
	}

	engine := NewReportEngine(&ReportConfig{})
	m.RiskScore = engine.CalculateRiskScore(findings)

	return m
}

func GetP0Count(findings []Finding) int {
	count := 0
	for _, f := range findings {
		if f.Severity == types.SeverityCritical {
			count++
		}
	}
	return count
}

func GetP1Count(findings []Finding) int {
	count := 0
	for _, f := range findings {
		if f.Severity == types.SeverityHigh {
			count++
		}
	}
	return count
}
