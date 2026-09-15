package ai

import (
	"testing"
)

func TestPromptInjection(t *testing.T) {
	engine := NewEngine(AIConfig{
		TargetURL:   "https://api.openai.com/v1/chat/completions",
		ModelName:   "gpt-4",
		MaxTokens:   4096,
		Temperature: 0.7,
	})

	result := engine.PromptInjection("https://api.example.com")

	if len(result.Attacks) == 0 {
		t.Error("Expected attacks")
	}
	for _, attack := range result.Attacks {
		if attack.Type != AttackTypePromptInjection {
			t.Error("Expected PromptInjection type")
		}
		if attack.Prompt == "" {
			t.Error("Prompt should not be empty")
		}
	}
}

func TestModelStealing(t *testing.T) {
	engine := NewEngine(AIConfig{ModelName: "gpt-4"})

	result := engine.ModelStealing("https://api.example.com")

	if len(result.Attacks) == 0 {
		t.Error("Expected attacks")
	}
	if len(result.Vulns) == 0 {
		t.Error("Expected vulnerabilities")
	}
}

func TestAdversarialExample(t *testing.T) {
	engine := NewEngine(AIConfig{Perturbation: 0.01})

	result := engine.AdversarialExample()

	if len(result.Attacks) == 0 {
		t.Error("Expected adversarial examples")
	}
	for _, attack := range result.Attacks {
		if attack.Type != AttackTypeAdversarialExample {
			t.Error("Expected AdversarialExample type")
		}
	}
}

func TestJailbreak(t *testing.T) {
	engine := NewEngine(AIConfig{})

	result := engine.Jailbreak()

	if len(result.Jailbreaks) == 0 {
		t.Error("Expected jailbreak results")
	}
	successCount := 0
	for _, j := range result.Jailbreaks {
		if j.Success {
			successCount++
		}
	}
	if successCount == 0 {
		t.Error("Expected at least one successful jailbreak")
	}
}

func TestScoreCalculation(t *testing.T) {
	engine := NewEngine(AIConfig{})

	result := engine.PromptInjection("https://api.example.com")
	if result.Score < 0 || result.Score > 100 {
		t.Errorf("Score should be 0-100, got %d", result.Score)
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(AIConfig{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
}

func TestAttackTypes(t *testing.T) {
	types := []AttackType{
		AttackTypePromptInjection, AttackTypeModelStealing,
		AttackTypeAdversarialExample, AttackTypeJailbreak,
	}
	for _, at := range types {
		if at.String() == "" {
			t.Errorf("AttackType %d should have string", at)
		}
	}
}
