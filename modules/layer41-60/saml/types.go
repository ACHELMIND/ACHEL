package saml

import "time"

type SAMLConfig struct {
	Issuer      string        `json:"issuer"`
	ACSURL      string        `json:"acs_url"`
	NameIDFmt   string        `json:"name_id_fmt"`
	Destination string        `json:"destination"`
	CertPEM     string        `json:"cert_pem"`
	KeyPEM      string        `json:"key_pem"`
	Timeout     time.Duration `json:"timeout"`
}

type SAMLResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Payload  string        `json:"payload"`
	Risk     string        `json:"risk"`
}

type SAMLAttack struct {
	AssertionID  string `json:"assertion_id"`
	NameID       string `json:"name_id"`
	Subject      string `json:"subject"`
	InResponseTo string `json:"in_response_to"`
	Issuer       string `json:"issuer"`
	SessionIndex string `json:"session_index"`
}

type OIDCAttack struct {
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	ResponseType string `json:"response_type"`
	Scope        string `json:"scope"`
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
}

type OAuthAttack struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	GrantType   string `json:"grant_type"`
	Scope       string `json:"scope"`
	State       string `json:"state"`
}

type SAMLAssertion struct {
	ID           string    `json:"id"`
	IssueInstant time.Time `json:"issue_instant"`
	Issuer       string    `json:"issuer"`
	NameID       string    `json:"name_id"`
	NameIDFormat string    `json:"name_id_format"`
	SessionIndex string    `json:"session_index"`
	Conditions   []string  `json:"conditions"`
	Attributes   map[string]string `json:"attributes"`
}

type SAMLResponse struct {
	ID              string            `json:"id"`
	IssueInstant    time.Time         `json:"issue_instant"`
	Destination     string            `json:"destination"`
	AssertionID     string            `json:"assertion_id"`
	Status          string            `json:"status"`
	Assertions      []SAMLAssertion   `json:"assertions"`
	SignatureValue  string            `json:"signature_value"`
	CertThumbprint  string            `json:"cert_thumbprint"`
}

type OIDCCodeFlow struct {
	AuthorizationURL string            `json:"authorization_url"`
	TokenURL         string            `json:"token_url"`
	UserInfoURL      string            `json:"userinfo_url"`
	Scopes           []string          `json:"scopes"`
	Claims           map[string]string `json:"claims"`
}

type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}
