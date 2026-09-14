package report

import (
	"fmt"

	"github.com/angel-platform/angel/pkg/types"
)

type ExecutiveSummaryGen struct {
	config *ReportConfig
}

func NewExecutiveSummaryGen(config *ReportConfig) *ExecutiveSummaryGen {
	return &ExecutiveSummaryGen{config: config}
}

func (es *ExecutiveSummaryGen) Generate(findings []Finding) (*ExecutiveSummary, error) {
	if findings == nil {
		findings = make([]Finding, 0)
	}

	summary := &ExecutiveSummary{
		TotalFindings: len(findings),
	}

	for _, f := range findings {
		switch f.Severity {
		case types.SeverityCritical:
			summary.CriticalCount++
		case types.SeverityHigh:
			summary.HighCount++
		case types.SeverityMedium:
			summary.MediumCount++
		case types.SeverityLow:
			summary.LowCount++
		}
	}

	engine := NewReportEngine(es.config)
	summary.RiskScore = engine.CalculateRiskScore(findings)

	summary.Summary = fmt.Sprintf(
		"This assessment identified %d security findings: %d critical, %d high, %d medium, and %d low severity issues. Overall risk score: %.2f/10.0.",
		summary.TotalFindings,
		summary.CriticalCount,
		summary.HighCount,
		summary.MediumCount,
		summary.LowCount,
		summary.RiskScore,
	)

	return summary, nil
}

func (es *ExecutiveSummaryGen) CalculateROI(spend float64, findings []Finding) float64 {
	if spend <= 0 {
		return 0
	}

	value := 0.0
	for _, f := range findings {
		switch f.Severity {
		case types.SeverityCritical:
			value += 50000.0
		case types.SeverityHigh:
			value += 20000.0
		case types.SeverityMedium:
			value += 5000.0
		case types.SeverityLow:
			value += 1000.0
		}
	}

	return (value - spend) / spend * 100
}
