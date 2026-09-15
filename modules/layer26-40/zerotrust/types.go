package zerotrust

import "time"

type IdentityAttack int

const (
	IdentityAttackMFABypass IdentityAttack = iota
	IdentityAttackSSOAbuse
	IdentityAttackTokenReplay
	IdentityAttackSessionHijack
	IdentityAttackPasswordSpray
	IdentityAttackOAuthAbuse
)

func (i IdentityAttack) String() string {
	return [...]string{
		"MFABypass", "SSOAbuse", "TokenReplay",
		"SessionHijack", "PasswordSpray", "OAuthAbuse",
	}[i]
}

type NetworkBypass int

const (
	NetworkBypassMicroSeg NetworkBypass = iota
	NetworkBypassEastWest
	NetworkBypassVPN
	NetworkBypassNAC
	NetworkBypassFirewall
	NetworkBypassDNS
)

func (n NetworkBypass) String() string {
	return [...]string{
		"MicroSeg", "EastWest", "VPN", "NAC", "Firewall", "DNS",
	}[n]
}

type ZeroTrustConfig struct {
	TargetDomain    string
	IDPProvider     string
	SSOEndpoint     string
	MFAMethod       string
	NetworkRange    string
	PolicyEngine    string
	TokenFile       string
	SSOToken        string
	AccessPolicies  []AccessPolicy
}

type ZTResult struct {
	ID              string                `json:"id"`
	IdentityResults []IdentityResult      `json:"identity_results"`
	NetworkResults  []NetworkBypassResult  `json:"network_results"`
	PolicyFindings  []PolicyFinding       `json:"policy_findings"`
	Score           int                    `json:"score"`
	Timestamp       time.Time              `json:"timestamp"`
}

type IdentityResult struct {
	Attack     IdentityAttack `json:"attack"`
	Success    bool           `json:"success"`
	Details    string         `json:"details"`
	Token      string         `json:"token,omitempty"`
	Session    string         `json:"session,omitempty"`
}

type NetworkBypassResult struct {
	Type       NetworkBypass `json:"type"`
	Success    bool          `json:"success"`
	Details    string        `json:"details"`
	Segment    string        `json:"segment"`
}

type PolicyFinding struct {
	Policy      string `json:"policy"`
	Issue       string `json:"issue"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
}

type AccessPolicy struct {
	Name    string   `json:"name"`
	Effect  string   `json:"effect"`
	Principals []string `json:"principals"`
	Resources []string `json:"resources"`
	Conditions []string `json:"conditions"`
}

type MFAConfig struct {
	Provider    string
	Method      string
	BypassToken string
	SIMSwap     bool
}

type SSOConfig struct {
	Issuer      string
	Audience    string
	TokenFile   string
	RefreshToken string
}
