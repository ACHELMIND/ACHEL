package compliance

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(ComplianceConfig{
		Framework: "PCI-DSS",
		Scope:     []string{"web", "database"},
	})
}

func TestPCICompliance(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.PCICompliance([]string{"web", "database"})
	if err != nil {
		t.Fatalf("PCICompliance failed: %v", err)
	}
	if !result.Success {
		t.Error("PCICompliance reported failure")
	}
	if result.Method != "PCI_DSS" {
		t.Errorf("expected method PCI_DSS, got %s", result.Method)
	}
	if result.Score == 0 {
		t.Error("score should not be zero")
	}
}

func TestPCIComplianceFindsFailures(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.PCICompliance([]string{"web"})
	if err != nil {
		t.Fatalf("PCICompliance failed: %v", err)
	}
	hasFailure := false
	for _, f := range result.Findings {
		if strings.Contains(f, "fail") || strings.Contains(f, "Default") {
			hasFailure = true
		}
	}
	if !hasFailure {
		t.Error("should find control failures")
	}
}

func TestGDPRCheck(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.GDPRCheck([]string{"web"})
	if err != nil {
		t.Fatalf("GDPRCheck failed: %v", err)
	}
	if !result.Success {
		t.Error("GDPRCheck reported failure")
	}
	if result.Method != "GDPR" {
		t.Errorf("expected method GDPR, got %s", result.Method)
	}
}

func TestNISTAssess(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.NISTAssess([]string{"web"})
	if err != nil {
		t.Fatalf("NISTAssess failed: %v", err)
	}
	if !result.Success {
		t.Error("NISTAssess reported failure")
	}
	if result.Method != "NIST_800_53" {
		t.Errorf("expected method NIST_800_53, got %s", result.Method)
	}
}

func TestCISBenchmark(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CISBenchmark([]string{"web"})
	if err != nil {
		t.Fatalf("CISBenchmark failed: %v", err)
	}
	if !result.Success {
		t.Error("CISBenchmark reported failure")
	}
	if result.Method != "CIS_Benchmark" {
		t.Errorf("expected method CIS_Benchmark, got %s", result.Method)
	}
}

func TestGenerateReport(t *testing.T) {
	eng := newTestEngine()
	controls := []ControlCheck{
		{ID: "1", Name: "Test1", Status: "pass"},
		{ID: "2", Name: "Test2", Status: "fail"},
		{ID: "3", Name: "Test3", Status: "warning"},
	}
	report := eng.GenerateReport("PCI-DSS", controls)
	if report.Passed != 1 {
		t.Errorf("expected 1 passed, got %d", report.Passed)
	}
	if report.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", report.Failed)
	}
	if report.Warning != 1 {
		t.Errorf("expected 1 warning, got %d", report.Warning)
	}
}

func TestGapAnalysis(t *testing.T) {
	eng := newTestEngine()
	current := []string{"firewall", "encryption"}
	required := []string{"firewall", "encryption", "logging", "monitoring", "backup", "incident_response"}
	gap := eng.GapAnalysis(current, required)
	if len(gap.Gaps) != 4 {
		t.Errorf("expected 4 gaps, got %d", len(gap.Gaps))
	}
	if gap.Priority != "critical" {
		t.Errorf("expected critical priority, got %s", gap.Priority)
	}
}

func TestGapAnalysisNoGaps(t *testing.T) {
	eng := newTestEngine()
	current := []string{"a", "b", "c"}
	required := []string{"a", "b"}
	gap := eng.GapAnalysis(current, required)
	if len(gap.Gaps) != 0 {
		t.Errorf("expected 0 gaps, got %d", len(gap.Gaps))
	}
}
