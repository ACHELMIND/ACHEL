package report

import (
	"fmt"
	"math"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type ReportEngine struct {
	config *ReportConfig
}

func NewReportEngine(config *ReportConfig) *ReportEngine {
	return &ReportEngine{config: config}
}

func (re *ReportEngine) GenerateReport(engagement *Engagement) (*Report, error) {
	if engagement == nil {
		return nil, fmt.Errorf("engagement is required")
	}

	report := &Report{
		ID:         types.GenerateID(),
		Title:      re.config.Title,
		Engagement: engagement.Name,
		CreatedAt:  time.Now().UTC(),
		Author:     re.config.Author,
		Sections:   make([]Section, 0),
	}

	summary, err := re.GenerateExecutiveSummary(engagement.Findings)
	if err != nil {
		return nil, fmt.Errorf("generate summary: %w", err)
	}

	report.Sections = append(report.Sections, Section{
		Name:    "Executive Summary",
		Content: summary,
	})

	riskScore := re.CalculateRiskScore(engagement.Findings)
	report.Sections = append(report.Sections, Section{
		Name:    "Risk Assessment",
		Content: fmt.Sprintf("Overall Risk Score: %.2f/10.0", riskScore),
	})

	return report, nil
}

func (re *ReportEngine) GenerateExecutiveSummary(findings []Finding) (string, error) {
	metrics := CalculateMetrics(findings)

	summary := fmt.Sprintf(
		"Security Assessment Report\n\n"+
			"Total Findings: %d\n"+
			"Critical: %d\n"+
			"High: %d\n"+
			"Medium: %d\n"+
			"Low: %d\n"+
			"Risk Score: %.2f/10.0",
		metrics.Total,
		metrics.Breakdown.Critical,
		metrics.Breakdown.High,
		metrics.Breakdown.Medium,
		metrics.Breakdown.Low,
		metrics.RiskScore,
	)

	return summary, nil
}

func (re *ReportEngine) CalculateRiskScore(findings []Finding) float64 {
	if len(findings) == 0 {
		return 0
	}

	score := 0.0
	for _, f := range findings {
		switch f.Severity {
		case types.SeverityCritical:
			score += 10.0
		case types.SeverityHigh:
			score += 7.0
		case types.SeverityMedium:
			score += 4.0
		case types.SeverityLow:
			score += 1.0
		}
	}

	normalized := math.Min(score/float64(len(findings))*2, 10.0)
	return math.Round(normalized*100) / 100
}
