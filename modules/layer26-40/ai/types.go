package ai

import "time"

type AttackType int

const (
	AttackTypePromptInjection AttackType = iota
	AttackTypeModelStealing
	AttackTypeAdversarialExample
	AttackTypeJailbreak
	AttackTypeDataExfil
	AttackTypeModelInversion
	AttackTypeMembershipInference
	AttackTypeBackdoor
)

func (a AttackType) String() string {
	return [...]string{
		"PromptInjection", "ModelStealing", "AdversarialExample",
		"Jailbreak", "DataExfil", "ModelInversion",
		"MembershipInference", "Backdoor",
	}[a]
}

type AIConfig struct {
	TargetURL    string
	APIKey       string
	ModelName    string
	AttackType   AttackType
	Prompts      []string
	MaxTokens    int
	Temperature  float64
	Epochs       int
	Perturbation float64
}

type AIResult struct {
	ID            string           `json:"id"`
	TargetURL     string           `json:"target_url"`
	ModelName     string           `json:"model_name"`
	Attacks       []AttackResult   `json:"attacks"`
	Jailbreaks    []JailbreakResult `json:"jailbreaks"`
	Vulns         []ModelVuln      `json:"vulnerabilities"`
	Score         int              `json:"score"`
	Timestamp     time.Time        `json:"timestamp"`
}

type PromptInjection struct {
	Prompt      string   `json:"prompt"`
	Type        string   `json:"type"`
	Payload     string   `json:"payload"`
	Encoding    string   `json:"encoding"`
	Techniques  []string `json:"techniques"`
}

type AttackResult struct {
	Type       AttackType `json:"type"`
	Success    bool       `json:"success"`
	Prompt     string     `json:"prompt"`
	Response   string     `json:"response"`
	Score      float64    `json:"score"`
	Details    string     `json:"details"`
}

type JailbreakResult struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Prompt     string   `json:"prompt"`
	Response   string   `json:"response"`
	Success    bool     `json:"success"`
	Severity   string   `json:"severity"`
}

type ModelVuln struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Evidence    string `json:"evidence"`
}
