package purpleteam

import (
	"testing"
)

func TestAlertValidation(t *testing.T) {
	engine := NewEngine(PurpleTeamConfig{
		MITREVersion: "14.1",
	})

	validations := engine.AlertValidation("alert-001")

	if len(validations) == 0 {
		t.Error("Expected validations")
	}
	for _, v := range validations {
		if v.AlertID == "" {
			t.Error("Alert ID should not be empty")
		}
		if v.RuleName == "" {
			t.Error("Rule name should not be empty")
		}
	}
}

func TestDetectionRuleTest(t *testing.T) {
	engine := NewEngine(PurpleTeamConfig{})

	tests := engine.DetectionRuleTest()

	if len(tests) == 0 {
		t.Error("Expected tests")
	}
	for _, test := range tests {
		if test.TechniqueID == "" {
			t.Error("Technique ID should not be empty")
		}
		if test.Tactic == "" {
			t.Error("Tactic should not be empty")
		}
	}
}

func TestLogCoverageTest(t *testing.T) {
	engine := NewEngine(PurpleTeamConfig{})

	coverage := engine.LogCoverageTest()

	if len(coverage) == 0 {
		t.Error("Expected coverage mappings")
	}
	for _, cov := range coverage {
		if cov.TacticID == "" {
			t.Error("Tactic ID should not be empty")
		}
		if cov.TotalCount == 0 {
			t.Error("Total count should be > 0")
		}
	}
}

func TestMITREMapping(t *testing.T) {
	engine := NewEngine(PurpleTeamConfig{})

	mappings := engine.MITREMapping([]string{"T1566", "T1059", "T1003"})

	if len(mappings) == 0 {
		t.Error("Expected mappings")
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(PurpleTeamConfig{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
	if engine.config.MITREVersion != "14.1" {
		t.Error("Default MITRE version should be set")
	}
}
