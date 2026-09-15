package passwordreset

type ResetFlow int

const (
	ResetFlowEmailToken ResetFlow = iota
	ResetFlowSMSCode
	ResetFlowSecurityQuestion
	ResetFlowMagicLink
	ResetFlowOAuth
)

func (f ResetFlow) String() string {
	return [...]string{
		"EmailToken", "SMSCode", "SecurityQuestion", "MagicLink", "OAuth",
	}[f]
}

type TokenAnalysis struct {
	TokenLength    int    `json:"token_length"`
	Entropy        float64 `json:"entropy"`
	IsPredictable  bool   `json:"is_predictable"`
	ContainsTimestamp bool `json:"contains_timestamp"`
	Pattern        string `json:"pattern"`
	CharacterSet   string `json:"character_set"`
}

type PasswordResetConfig struct {
	TargetURL      string            `json:"target_url"`
	Email          string            `json:"email"`
	ResetEndpoint  string            `json:"reset_endpoint"`
	Flow           ResetFlow         `json:"flow"`
	Headers        map[string]string `json:"headers"`
	NumSamples     int               `json:"num_samples"`
}

type PasswordResetResult struct {
	Flow           ResetFlow     `json:"flow"`
	Vulnerable     bool          `json:"vulnerable"`
	TokenAnalysis  *TokenAnalysis `json:"token_analysis,omitempty"`
	HostHeaderVuln bool          `json:"host_header_vuln"`
	TokenLeak      bool          `json:"token_leak"`
	Details        string        `json:"details"`
	Remediation    string        `json:"remediation"`
	RiskScore      float64       `json:"risk_score"`
}

type HostInjection struct {
	Header       string `json:"header"`
	Value        string `json:"value"`
	RedirectURL  string `json:"redirect_url"`
	Success      bool   `json:"success"`
}
