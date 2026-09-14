package report

import (
	"testing"

	"github.com/angel-platform/angel/pkg/types"
)

func TestReportEngineGenerate(t *testing.T) {
	config := &ReportConfig{
		Title:      "Test Report",
		Engagement: "Test Engagement",
		Author:     "tester",
	}

	engine := NewReportEngine(config)

	engagement := &Engagement{
		ID:   "eng-001",
		Name: "Test Engagement",
		Findings: []Finding{
			{ID: "f1", Title: "SQL Injection", Severity: types.SeverityCritical, Category: "injection"},
			{ID: "f2", Title: "XSS", Severity: types.SeverityHigh, Category: "xss"},
		},
	}

	report, err := engine.GenerateReport(engagement)
	if err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}

	if report.Title != "Test Report" {
		t.Errorf("Expected title 'Test Report', got '%s'", report.Title)
	}
	if len(report.Sections) < 2 {
		t.Errorf("Expected at least 2 sections, got %d", len(report.Sections))
	}
}

func TestReportEngineNilEngagement(t *testing.T) {
	engine := NewReportEngine(&ReportConfig{})

	_, err := engine.GenerateReport(nil)
	if err == nil {
		t.Error("Expected error for nil engagement")
	}
}

func TestReportEngineCalculateRiskScore(t *testing.T) {
	engine := NewReportEngine(&ReportConfig{})

	findings := []Finding{
		{Severity: types.SeverityCritical},
		{Severity: types.SeverityHigh},
	}

	score := engine.CalculateRiskScore(findings)
	if score <= 0 || score > 10 {
		t.Errorf("Expected risk score between 0 and 10, got %.2f", score)
	}
}

func TestReportEngineCalculateRiskScoreEmpty(t *testing.T) {
	engine := NewReportEngine(&ReportConfig{})

	score := engine.CalculateRiskScore(nil)
	if score != 0 {
		t.Errorf("Expected 0 for empty findings, got %.2f", score)
	}
}

func TestTechnicalReportGenerate(t *testing.T) {
	config := &ReportConfig{Title: "Tech Report", Author: "tester"}
	gen := NewTechnicalReportGen(config)

	findings := []Finding{
		{ID: "f1", Title: "Test", Severity: types.SeverityHigh, Category: "test", Description: "desc", Impact: "impact", Remediation: "fix"},
	}

	report, err := gen.Generate(findings, []string{"evidence1.png"})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(report.Findings))
	}
}

func TestTechnicalReportRenderMarkdown(t *testing.T) {
	config := &ReportConfig{Title: "MD Report", Author: "tester"}
	gen := NewTechnicalReportGen(config)

	gen.AddSection("Custom", "Custom content")

	md := gen.RenderMarkdown()
	if len(md) == 0 {
		t.Error("Expected non-empty markdown")
	}
}

func TestTechnicalReportRenderJSON(t *testing.T) {
	config := &ReportConfig{Title: "JSON Report", Author: "tester"}
	gen := NewTechnicalReportGen(config)

	gen.AddSection("Test", "Content")

	data, err := gen.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("Expected non-empty JSON")
	}
}

func TestExecutiveSummaryGenerate(t *testing.T) {
	config := &ReportConfig{Title: "Exec Report"}
	gen := NewExecutiveSummaryGen(config)

	findings := []Finding{
		{Severity: types.SeverityCritical},
		{Severity: types.SeverityCritical},
		{Severity: types.SeverityHigh},
		{Severity: types.SeverityMedium},
		{Severity: types.SeverityLow},
	}

	summary, err := gen.Generate(findings)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if summary.TotalFindings != 5 {
		t.Errorf("Expected 5 findings, got %d", summary.TotalFindings)
	}
	if summary.CriticalCount != 2 {
		t.Errorf("Expected 2 critical, got %d", summary.CriticalCount)
	}
	if summary.HighCount != 1 {
		t.Errorf("Expected 1 high, got %d", summary.HighCount)
	}
}

func TestExecutiveSummaryCalculateROI(t *testing.T) {
	gen := NewExecutiveSummaryGen(&ReportConfig{})

	findings := []Finding{
		{Severity: types.SeverityCritical},
		{Severity: types.SeverityHigh},
	}

	roi := gen.CalculateROI(10000, findings)
	if roi <= 0 {
		t.Errorf("Expected positive ROI, got %.2f", roi)
	}
}

func TestExecutiveSummaryCalculateROIZeroSpend(t *testing.T) {
	gen := NewExecutiveSummaryGen(&ReportConfig{})

	roi := gen.CalculateROI(0, []Finding{{Severity: types.SeverityCritical}})
	if roi != 0 {
		t.Errorf("Expected 0 for zero spend, got %.2f", roi)
	}
}

func TestCalculateMetrics(t *testing.T) {
	findings := []Finding{
		{Severity: types.SeverityCritical, Category: "injection"},
		{Severity: types.SeverityHigh, Category: "xss"},
		{Severity: types.SeverityMedium, Category: "injection"},
	}

	metrics := CalculateMetrics(findings)

	if metrics.Total != 3 {
		t.Errorf("Expected total 3, got %d", metrics.Total)
	}
	if metrics.Breakdown.Critical != 1 {
		t.Errorf("Expected 1 critical, got %d", metrics.Breakdown.Critical)
	}
	if metrics.Categories["injection"] != 2 {
		t.Errorf("Expected 2 injection findings, got %d", metrics.Categories["injection"])
	}
}

func TestGetP0Count(t *testing.T) {
	findings := []Finding{
		{Severity: types.SeverityCritical},
		{Severity: types.SeverityCritical},
		{Severity: types.SeverityHigh},
	}

	count := GetP0Count(findings)
	if count != 2 {
		t.Errorf("Expected 2 P0, got %d", count)
	}
}

func TestGetP1Count(t *testing.T) {
	findings := []Finding{
		{Severity: types.SeverityHigh},
		{Severity: types.SeverityHigh},
		{Severity: types.SeverityMedium},
	}

	count := GetP1Count(findings)
	if count != 2 {
		t.Errorf("Expected 2 P1, got %d", count)
	}
}

func TestExecutiveSummaryEmptyFindings(t *testing.T) {
	gen := NewExecutiveSummaryGen(&ReportConfig{})

	summary, err := gen.Generate(nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if summary.TotalFindings != 0 {
		t.Errorf("Expected 0 findings, got %d", summary.TotalFindings)
	}
}
