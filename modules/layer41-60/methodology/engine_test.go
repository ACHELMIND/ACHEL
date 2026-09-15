package methodology

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(MethodologyConfig{
		Scope: []string{"example.com"},
		Phase: "recon",
	})
}

func TestReconPhase(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.ReconPhase([]string{"example.com"})
	if err != nil {
		t.Fatalf("ReconPhase failed: %v", err)
	}
	if !result.Success {
		t.Error("ReconPhase reported failure")
	}
	if result.Method != "Recon_Phase" {
		t.Errorf("expected method Recon_Phase, got %s", result.Method)
	}
	if result.Score != 100 {
		t.Errorf("expected score 100, got %.0f", result.Score)
	}
}

func TestDiscoveryPhase(t *testing.T) {
	eng := newTestEngine()
	recon := ReconResult{
		Domains:  []string{"example.com"},
		IPs:      []string{"10.0.0.1"},
		Ports:    []int{80, 443},
		Services: []string{"HTTP"},
	}
	result, err := eng.DiscoveryPhase(recon)
	if err != nil {
		t.Fatalf("DiscoveryPhase failed: %v", err)
	}
	if !result.Success {
		t.Error("DiscoveryPhase reported failure")
	}
	if !strings.Contains(result.Message, "endpoints") {
		t.Error("should mention endpoints")
	}
}

func TestExploitationPhase(t *testing.T) {
	eng := newTestEngine()
	discovery := DiscoveryResult{
		Endpoints:  []string{"/login"},
		Parameters: []string{"user"},
	}
	result, err := eng.ExploitationPhase(discovery)
	if err != nil {
		t.Fatalf("ExploitationPhase failed: %v", err)
	}
	if !result.Success {
		t.Error("ExploitationPhase reported failure")
	}
	if len(result.Findings) == 0 {
		t.Error("should have findings")
	}
}

func TestReportingPhase(t *testing.T) {
	eng := newTestEngine()
	findings := []string{"SQL Injection", "XSS", "CSRF"}
	result, err := eng.ReportingPhase(findings)
	if err != nil {
		t.Fatalf("ReportingPhase failed: %v", err)
	}
	if !result.Success {
		t.Error("ReportingPhase reported failure")
	}
	if !strings.Contains(result.Message, "medium") {
		t.Error("should report medium risk for 3 findings")
	}
}

func TestGetOWASPCategories(t *testing.T) {
	eng := newTestEngine()
	categories := eng.GetOWASPCategories()
	if len(categories) == 0 {
		t.Error("should return OWASP categories")
	}
	if categories[0].ID != "A01" {
		t.Errorf("expected A01, got %s", categories[0].ID)
	}
}

func TestGetPhases(t *testing.T) {
	eng := newTestEngine()
	eng.ReconPhase([]string{"test.com"})
	eng.DiscoveryPhase(ReconResult{})
	phases := eng.GetPhases()
	if len(phases) != 2 {
		t.Errorf("expected 2 phases, got %d", len(phases))
	}
}

func TestReportingPhaseCritical(t *testing.T) {
	eng := newTestEngine()
	findings := make([]string, 20)
	for i := range findings {
		findings[i] = "finding"
	}
	result, err := eng.ReportingPhase(findings)
	if err != nil {
		t.Fatalf("ReportingPhase failed: %v", err)
	}
	if !strings.Contains(result.Message, "critical") {
		t.Error("should report critical risk for many findings")
	}
}

func TestExploitationScore(t *testing.T) {
	eng := newTestEngine()
	result := ExploitationResult{
		Vulns:  []string{"v1", "v2"},
		Impact: "low",
	}
	score := eng.calculateExploitationScore(result)
	if score != 80 {
		t.Errorf("expected 80, got %.0f", score)
	}
}
