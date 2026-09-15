package authbypass

import (
	"time"
)

type AuthBypassMethod string

const (
	MethodSQLiAuth       AuthBypassMethod = "sqli_auth"
	MethodNoSQLAuth      AuthBypassMethod = "nosql_auth"
	MethodJWTBypass      AuthBypassMethod = "jwt_bypass"
	MethodJSONTampering  AuthBypassMethod = "json_tampering"
	MethodDefaultCred    AuthBypassMethod = "default_cred"
	MethodOAuthBypass    AuthBypassMethod = "oauth_bypass"
	MethodSessionHijack  AuthBypassMethod = "session_hijack"
)

type BypassResult struct {
	Success  bool              `json:"success"`
	Method   AuthBypassMethod  `json:"method"`
	Details  string            `json:"details"`
	Data     map[string]string `json:"data,omitempty"`
	Error    string            `json:"error,omitempty"`
	Duration time.Duration     `json:"duration"`
	Timestamp time.Time        `json:"timestamp"`
}

type AuthBypassConfig struct {
	Target          string            `json:"target"`
	Timeout         time.Duration     `json:"timeout"`
	Methods         []AuthBypassMethod `json:"methods"`
	UsernameField   string            `json:"username_field"`
	PasswordField   string            `json:"password_field"`
	LoginEndpoint   string            `json:"login_endpoint"`
	Verbose         bool              `json:"verbose"`
	CustomHeaders   map[string]string `json:"custom_headers,omitempty"`
}

func DefaultAuthBypassConfig() *AuthBypassConfig {
	return &AuthBypassConfig{
		Timeout:       30 * time.Second,
		Methods:       AllAuthBypassMethods(),
		UsernameField: "username",
		PasswordField: "password",
		LoginEndpoint: "/login",
		Verbose:       false,
	}
}

func AllAuthBypassMethods() []AuthBypassMethod {
	return []AuthBypassMethod{
		MethodSQLiAuth,
		MethodNoSQLAuth,
		MethodJWTBypass,
		MethodJSONTampering,
		MethodDefaultCred,
		MethodOAuthBypass,
		MethodSessionHijack,
	}
}

type JWTAlgorithm string

const (
	JWTAlgNone        JWTAlgorithm = "none"
	JWTAlgHS256       JWTAlgorithm = "HS256"
	JWTAlgRS256       JWTAlgorithm = "RS256"
	JWTAlgES256       JWTAlgorithm = "ES256"
)

type JWTAttackResult struct {
	Success   bool          `json:"success"`
	Algorithm JWTAlgorithm `json:"algorithm"`
	Token     string        `json:"token,omitempty"`
	Claims    string        `json:"claims,omitempty"`
	Error     string        `json:"error,omitempty"`
}

type BruteForceMethod string

const (
	BruteForceHTTP      BruteForceMethod = "http"
	BruteForceSSH       BruteForceMethod = "ssh"
	BruteForceFTP       BruteForceMethod = "ftp"
	BruteForceRDP       BruteForceMethod = "rdp"
	BruteForceSMTP      BruteForceMethod = "smtp"
)

type BruteforceConfig struct {
	Target       string            `json:"target"`
	Port         int               `json:"port"`
	Method       BruteForceMethod  `json:"method"`
	Username     string            `json:"username"`
	Wordlist     []string          `json:"wordlist"`
	MaxAttempts  int               `json:"max_attempts"`
	Delay        time.Duration     `json:"delay"`
	Timeout      time.Duration     `json:"timeout"`
	Threads      int               `json:"threads"`
}

type CredentialPair struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type BruteforceResult struct {
	Success      bool            `json:"success"`
	Credentials  *CredentialPair `json:"credentials,omitempty"`
	Attempts     int             `json:"attempts"`
	TotalTried   int             `json:"total_tried"`
	Error        string          `json:"error,omitempty"`
	Duration     time.Duration   `json:"duration"`
	Timestamp    time.Time       `json:"timestamp"`
}

type OAuthRedirectResult struct {
	Original   string `json:"original"`
	Manipulated string `json:"manipulated"`
	Domain     string `json:"domain"`
}

type OAuthScopeResult struct {
	Success  bool     `json:"success"`
	Original []string `json:"original"`
	Escalated []string `json:"escalated"`
	Error    string   `json:"error,omitempty"`
}

type SessionFixationResult struct {
	Success   bool   `json:"success"`
	SessionID string `json:"session_id,omitempty"`
	URL       string `json:"url"`
	Error     string `json:"error,omitempty"`
}

type CookieAnalysis struct {
	URL              string            `json:"url"`
	Cookies          []CookieInfo      `json:"cookies"`
	Vulnerable       bool              `json:"vulnerable"`
	Issues           []string          `json:"issues,omitempty"`
}

type CookieInfo struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
}

type DeviceCodeResult struct {
	Success      bool   `json:"success"`
	DeviceCode   string `json:"device_code,omitempty"`
	UserCode     string `json:"user_code,omitempty"`
	VerificationURI string `json:"verification_uri,omitempty"`
	Error        string `json:"error,omitempty"`
}
