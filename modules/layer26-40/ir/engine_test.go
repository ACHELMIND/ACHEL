package ir

import (
	"testing"
)

func TestBreachSimulate(t *testing.T) {
	engine := NewEngine(IRConfig{
		Severity: "high",
	})

	result := engine.BreachSimulate([]string{"web-server", "database"})

	if len(result.Findings) == 0 {
		t.Error("Expected findings")
	}
	if len(result.Timeline) == 0 {
		t.Error("Expected timeline")
	}
	if result.Metrics.TotalFindings == 0 {
		t.Error("Expected total findings > 0")
	}
}

func TestContainment(t *testing.T) {
	engine := NewEngine(IRConfig{})

	result := engine.Containment([]string{"finding-1"})

	if result.Phase != IRPhaseContainment {
		t.Errorf("Expected Containment phase, got %v", result.Phase)
	}
	if len(result.Actions) == 0 {
		t.Error("Expected containment actions")
	}
}

func TestEradication(t *testing.T) {
	engine := NewEngine(IRConfig{})

	result := engine.Eradication([]Finding{{ID: "f1", Title: "Malware"}})

	if result.Phase != IRPhaseEradication {
		t.Errorf("Expected Eradication phase, got %v", result.Phase)
	}
	if len(result.Actions) == 0 {
		t.Error("Expected eradication actions")
	}
}

func TestRecovery(t *testing.T) {
	engine := NewEngine(IRConfig{})

	result := engine.Recovery([]Finding{{ID: "f1", Title: "Contained"}})

	if result.Phase != IRPhaseRecovery {
		t.Errorf("Expected Recovery phase, got %v", result.Phase)
	}
	if len(result.Actions) == 0 {
		t.Error("Expected recovery actions")
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(IRConfig{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
}

func TestIRPhases(t *testing.T) {
	phases := []IRPhase{
		IRPhasePreparation, IRPhaseIdentification, IRPhaseContainment,
		IRPhaseEradication, IRPhaseRecovery, IRPhaseLessons,
	}
	for _, p := range phases {
		if p.String() == "" {
			t.Errorf("IRPhase %d should have string", p)
		}
	}
}
