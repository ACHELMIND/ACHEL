package orchestrator

import (
	"testing"
	"time"
)

func TestOrchestratorNew(t *testing.T) {
	orch := New(nil)
	if orch == nil {
		t.Fatal("expected non-nil orchestrator")
	}
	if orch.config.MaxAgents != 10 {
		t.Errorf("expected max agents 10, got %d", orch.config.MaxAgents)
	}
}

func TestOrchestratorExecute(t *testing.T) {
	orch := New(nil)
	err := orch.Execute("scan target.com")
	if err != nil {
		t.Errorf("execution failed: %v", err)
	}
}

func TestOrchestratorStatus(t *testing.T) {
	orch := New(nil)
	status := orch.GetStatus()
	if status == nil {
		t.Fatal("expected non-nil status")
	}
	if _, ok := status["running"]; !ok {
		t.Error("expected running field in status")
	}
}

func TestOrchestratorStop(t *testing.T) {
	orch := New(nil)
	go func() {
		orch.Execute("scan target.com")
	}()
	time.Sleep(100 * time.Millisecond)
	orch.Stop()
	if orch.running {
		t.Error("expected orchestrator to be stopped")
	}
}

func TestOrchestratorReset(t *testing.T) {
	orch := New(nil)
	orch.Execute("scan target.com")
	orch.Reset()
	if len(orch.state.Actions) != 0 {
		t.Error("expected empty actions after reset")
	}
}

func TestOrchestratorWithConfig(t *testing.T) {
	cfg := &Config{
		MaxAgents:      5,
		MaxMCPsessions: 3,
		TaskTimeout:    2 * time.Minute,
		EnableFireteam: true,
		EnableMCP:      true,
		EnableBrain:    true,
	}
	orch := New(cfg)
	if orch.config.MaxAgents != 5 {
		t.Errorf("expected max agents 5, got %d", orch.config.MaxAgents)
	}
}
