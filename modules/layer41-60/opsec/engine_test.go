package opsec

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(OPSECConfig{
		Project: "pentest-001",
		Team:    "red-team",
	})
}

func TestCommChannelSetupTor(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CommChannelSetup("tor")
	if err != nil {
		t.Fatalf("CommChannelSetup failed: %v", err)
	}
	if !result.Success {
		t.Error("CommChannelSetup reported failure")
	}
	if result.Method != "Comm_Channel_Setup" {
		t.Errorf("expected method Comm_Channel_Setup, got %s", result.Method)
	}
}

func TestCommChannelSetupVPN(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CommChannelSetup("vpn")
	if err != nil {
		t.Fatalf("CommChannelSetup failed: %v", err)
	}
	if !result.Success {
		t.Error("CommChannelSetup reported failure")
	}
}

func TestTrafficAnalysis(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.TrafficAnalysis("10.0.0.1", "10.0.0.2")
	if err != nil {
		t.Fatalf("TrafficAnalysis failed: %v", err)
	}
	if !result.Success {
		t.Error("TrafficAnalysis reported failure")
	}
	if result.Method != "Traffic_Analysis" {
		t.Errorf("expected method Traffic_Analysis, got %s", result.Method)
	}
}

func TestRiskAssessment(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.RiskAssessment([]string{"web", "database"})
	if err != nil {
		t.Fatalf("RiskAssessment failed: %v", err)
	}
	if !result.Success {
		t.Error("RiskAssessment reported failure")
	}
	if len(result.Details) == 0 {
		t.Error("should have risk details")
	}
}

func TestCleanupVerify(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CleanupVerify([]string{"clear_history", "remove_temp"})
	if err != nil {
		t.Fatalf("CleanupVerify failed: %v", err)
	}
	if !result.Success {
		t.Error("CleanupVerify reported failure")
	}
	if !strings.Contains(result.Message, "processed") {
		t.Error("should mention processed")
	}
}

func TestRiskScore(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.RiskAssessment([]string{"web"})
	if err != nil {
		t.Fatalf("RiskAssessment failed: %v", err)
	}
	if result.RiskScore < 0 || result.RiskScore > 100 {
		t.Errorf("risk score out of range: %d", result.RiskScore)
	}
}

func TestCleanupVerifyMultiple(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CleanupVerify([]string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("CleanupVerify failed: %v", err)
	}
	if len(result.Details) < 3 {
		t.Error("should have at least 3 result details")
	}
}

func TestCommChannelSetupUnknown(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CommChannelSetup("unknown")
	if err != nil {
		t.Fatalf("CommChannelSetup failed: %v", err)
	}
	if result.RiskScore < 50 {
		t.Error("unknown channel should have higher risk")
	}
}
