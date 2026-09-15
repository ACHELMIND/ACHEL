package passwordreset

import "testing"

func TestTokenPredictable(t *testing.T) {
	config := PasswordResetConfig{
		TargetURL:     "http://target/reset",
		Email:         "user@test.com",
		ResetEndpoint: "/api/reset",
		NumSamples:    20,
	}
	engine := NewEngine(config)
	result := engine.TokenPredictable()
	if result.Flow != ResetFlowEmailToken {
		t.Errorf("expected EmailToken flow, got %d", result.Flow)
	}
	if result.TokenAnalysis == nil {
		t.Error("expected non-nil token analysis")
	}
}

func TestHostHeaderInject(t *testing.T) {
	config := PasswordResetConfig{
		TargetURL:     "http://target/reset",
		Email:         "user@test.com",
		ResetEndpoint: "/api/reset",
	}
	engine := NewEngine(config)
	result := engine.HostHeaderInject()
	if result.Flow != ResetFlowEmailToken {
		t.Errorf("expected EmailToken flow, got %d", result.Flow)
	}
}

func TestResetTokenLeak(t *testing.T) {
	config := PasswordResetConfig{
		TargetURL: "http://target/reset",
	}
	engine := NewEngine(config)
	result := engine.ResetTokenLeak()
	if result.Flow != ResetFlowEmailToken {
		t.Errorf("expected EmailToken flow, got %d", result.Flow)
	}
}

func TestPasswordReuse(t *testing.T) {
	config := PasswordResetConfig{
		TargetURL: "http://target/reset",
	}
	engine := NewEngine(config)
	result := engine.PasswordReuse()
	if !result.Vulnerable {
		t.Error("expected vulnerable result")
	}
	if result.RiskScore <= 0 {
		t.Error("expected positive risk score")
	}
}
