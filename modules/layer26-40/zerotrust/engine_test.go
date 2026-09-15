package zerotrust

import (
	"testing"
)

func TestMFABypass(t *testing.T) {
	engine := NewEngine(ZeroTrustConfig{})

	result := engine.MFABypass("sim_swap")

	if len(result.IdentityResults) == 0 {
		t.Error("Expected identity results")
	}
	if !result.IdentityResults[0].Success {
		t.Error("Expected successful MFA bypass")
	}
}

func TestSSOAbuse(t *testing.T) {
	engine := NewEngine(ZeroTrustConfig{})

	result := engine.SSOAbuse()

	if len(result.IdentityResults) < 2 {
		t.Error("Expected multiple SSO abuse results")
	}
	for _, ir := range result.IdentityResults {
		if ir.Token == "" && ir.Session == "" {
			// At least one should have token/session
		}
	}
}

func TestConditionalAccessBypass(t *testing.T) {
	engine := NewEngine(ZeroTrustConfig{})

	result := engine.ConditionalAccessBypass()

	if len(result.IdentityResults) == 0 {
		t.Error("Expected identity results")
	}
	if len(result.PolicyFindings) == 0 {
		t.Error("Expected policy findings")
	}
}

func TestMicroSegBypass(t *testing.T) {
	engine := NewEngine(ZeroTrustConfig{})

	result := engine.MicroSegBypass()

	if len(result.NetworkResults) == 0 {
		t.Error("Expected network bypass results")
	}
	bypassCount := 0
	for _, nr := range result.NetworkResults {
		if nr.Success {
			bypassCount++
		}
	}
	if bypassCount == 0 {
		t.Error("Expected at least one successful bypass")
	}
}

func TestScoreCalculation(t *testing.T) {
	engine := NewEngine(ZeroTrustConfig{})

	result := engine.MFABypass("test")
	if result.Score < 0 || result.Score > 100 {
		t.Errorf("Score should be 0-100, got %d", result.Score)
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(ZeroTrustConfig{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
}
