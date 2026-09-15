package api

import "time"

type AuthMethod int

const (
	AuthMethodBearer AuthMethod = iota
	AuthMethodAPIKey
	AuthMethodOAuth2
	AuthMethodBasicAuth
	AuthMethodJWT
	AuthMethodHMAC
	AuthMethodCookie
)

func (a AuthMethod) String() string {
	return [...]string{
		"Bearer", "APIKey", "OAuth2", "BasicAuth",
		"JWT", "HMAC", "Cookie",
	}[a]
}

type OAuthFlow int

const (
	OAuthFlowAuthorizationCode OAuthFlow = iota
	OAuthFlowImplicit
	OAuthFlowClientCredentials
	OAuthFlowResourceOwner
	OAuthFlowDeviceCode
)

func (o OAuthFlow) String() string {
	return [...]string{
		"AuthorizationCode", "Implicit", "ClientCredentials",
		"ResourceOwner", "DeviceCode",
	}[o]
}

type APIConfig struct {
	BaseURL       string
	AuthToken     string
	APIKey        string
	AuthMethod    AuthMethod
	OAuthConfig   *OAuthConfig
	Paths         []string
	Method        string
	Headers       map[string]string
	Body          string
	Timeout       time.Duration
	RateLimit     int
	VerifySSL     bool
	FollowRedirects bool
}

type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	AuthURL      string
	TokenURL     string
	Scope        string
	State        string
	Flow         OAuthFlow
}

type APIResult struct {
	ID            string              `json:"id"`
	BaseURL       string              `json:"base_url"`
	OAuthIssues   []OAuthIssue        `json:"oauth_issues"`
	JWTIssues     []JWTIssue          `json:"jwt_issues"`
	RateLimitFindings []RateLimitFinding `json:"rate_limit_findings"`
	IDORFindings  []IDORFinding       `json:"idor_findings"`
	Endpoints     []EndpointResult    `json:"endpoints"`
	Timestamp     time.Time           `json:"timestamp"`
}

type OAuthIssue struct {
	Flow        OAuthFlow `json:"flow"`
	Issue       string    `json:"issue"`
	Impact      string    `json:"impact"`
	Details     string    `json:"details"`
}

type JWTIssue struct {
	Algorithm   string `json:"algorithm"`
	Issue       string `json:"issue"`
	Impact      string `json:"impact"`
	Payload     string `json:"payload"`
	Token       string `json:"token"`
}

type RateLimitFinding struct {
	Path        string `json:"path"`
	Method      string `json:"method"`
	Limit       int    `json:"limit"`
	Bypass      string `json:"bypass"`
	Requests    int    `json:"requests_before_block"`
}

type IDORFinding struct {
	Path        string `json:"path"`
	Pattern     string `json:"pattern"`
	Parameter   string `json:"parameter"`
	Accessible  bool   `json:"accessible"`
	Details     string `json:"details"`
}

type EndpointResult struct {
	Path        string          `json:"path"`
	Method      string          `json:"method"`
	StatusCode  int             `json:"status_code"`
	Auth        AuthMethod      `json:"auth_required"`
	Headers     map[string]string `json:"headers"`
	Body        string          `json:"body,omitempty"`
}
