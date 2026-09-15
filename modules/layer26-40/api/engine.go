package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Engine struct {
	config APIConfig
}

func NewEngine(config APIConfig) *Engine {
	if config.BaseURL == "" {
		config.BaseURL = "https://api.example.com"
	}
	if config.RateLimit == 0 {
		config.RateLimit = 100
	}
	return &Engine{config: config}
}

func (e *Engine) OAuthRedirectAttack(oauthConfig OAuthConfig) APIResult {
	result := APIResult{
		ID:      uuid.New().String(),
		BaseURL: e.config.BaseURL,
		Timestamp: time.Now(),
	}

	issues := e.analyzeOAuthConfig(oauthConfig)
	result.OAuthIssues = issues

	if oauthConfig.RedirectURI != "" && !strings.HasPrefix(oauthConfig.RedirectURI, "https://") {
		result.OAuthIssues = append(result.OAuthIssues, OAuthIssue{
			Flow:    oauthConfig.Flow,
			Issue:   "Open redirect in redirect_uri parameter",
			Impact:  "Authorization code interception",
			Details: "Redirect URI accepts HTTP or has URL parameter that can be manipulated",
		})
	}

	stateMissing := oauthConfig.State == ""
	if stateMissing {
		result.OAuthIssues = append(result.OAuthIssues, OAuthIssue{
			Flow:    OAuthFlowAuthorizationCode,
			Issue:   "Missing state parameter",
			Impact:  "CSRF attack on authorization endpoint",
			Details: "No state parameter allows CSRF to link attacker account to victim session",
		})
	}

	return result
}

func (e *Engine) JWTAlgorithmBypass(token string) APIResult {
	result := APIResult{
		ID:      uuid.New().String(),
		BaseURL: e.config.BaseURL,
		Timestamp: time.Now(),
	}

	if token == "" {
		token = e.generateSampleJWT()
	}

	algIssues := e.analyzeJWT(token)
	result.JWTIssues = algIssues

	return result
}

func (e *Engine) RateLimitBypass(path string) APIResult {
	result := APIResult{
		ID:      uuid.New().String(),
		BaseURL: e.config.BaseURL,
		Timestamp: time.Now(),
	}

	findings := e.testRateLimits(path)
	result.RateLimitFindings = findings

	return result
}

func (e *Engine) IDOREnum(basePath string) APIResult {
	result := APIResult{
		ID:      uuid.New().String(),
		BaseURL: e.config.BaseURL,
		Timestamp: time.Now(),
	}

	idorFindings := e.detectIDORPatterns(basePath)
	result.IDORFindings = idorFindings

	return result
}

func (e *Engine) analyzeOAuthConfig(config OAuthConfig) []OAuthIssue {
	var issues []OAuthIssue

	if config.Flow == OAuthFlowImplicit {
		issues = append(issues, OAuthIssue{
			Flow:   config.Flow,
			Issue:  "Implicit flow is deprecated",
			Impact: "Token exposed in URL fragment, accessible via browser history",
		})
	}

	if config.ClientSecret == "" {
		issues = append(issues, OAuthIssue{
			Flow:   config.Flow,
			Issue:  "Empty client secret",
			Impact: "Public clients cannot securely store secrets",
		})
	}

	if config.Scope == "" || config.Scope == "*" {
		issues = append(issues, OAuthIssue{
			Flow:   config.Flow,
			Issue:  "Overly broad scope requested",
			Impact: "Excessive permissions granted to application",
		})
	}

	return issues
}

func (e *Engine) analyzeJWT(token string) []JWTIssue {
	var issues []JWTIssue

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		issues = append(issues, JWTIssue{
			Algorithm: "unknown",
			Issue:     "Invalid JWT format - expected 3 parts",
			Impact:    "Token processing failure",
		})
		return issues
	}

	headerJSON, err := base64RawURLEncodeDecode(parts[0])
	if err == nil {
		var header map[string]interface{}
		if json.Unmarshal(headerJSON, &header) == nil {
			alg, _ := header["alg"].(string)

			if alg == "none" {
				issues = append(issues, JWTIssue{
					Algorithm: alg,
					Issue:     "Algorithm 'none' accepted",
					Impact:    "Bypass signature verification entirely",
				})
			}

			if alg == "HS256" {
				issues = append(issues, JWTIssue{
					Algorithm: alg,
					Issue:     "HMAC algorithm with public key confusion possible",
					Impact:    "If server uses RSA public key as HMAC secret, token can be forged",
					Token:     token,
				})
			}

			if alg == "RS256" {
				issues = append(issues, JWTIssue{
					Algorithm: alg,
					Issue:     "RS256 to HS256 algorithm confusion possible",
					Impact:    "Sign token with public key instead of private key",
				})
			}

			weakAlgs := []string{"HS1", "HS256", "HS384"}
			for _, wa := range weakAlgs {
				if alg == wa {
					issues = append(issues, JWTIssue{
						Algorithm: alg,
						Issue:     fmt.Sprintf("Weak algorithm %s is susceptible to brute force", alg),
						Impact:    "Secret key can be recovered from known plaintext",
					})
				}
			}
		}
	}

	payloadJSON, err := base64RawURLEncodeDecode(parts[1])
	if err == nil {
		var payload map[string]interface{}
		if json.Unmarshal(payloadJSON, &payload) == nil {
			if exp, ok := payload["exp"].(float64); ok {
				if time.Now().Unix() > int64(exp) {
					issues = append(issues, JWTIssue{
						Issue:  "Token is expired but still accepted",
						Impact: "Expired tokens used for authentication",
					})
				}
			}
		}
	}

	return issues
}

func (e *Engine) testRateLimits(path string) []RateLimitFinding {
	var findings []RateLimitFinding

	bypasses := []struct {
		name   string
		header string
		value  string
	}{
		{"X-Forwarded-For", "X-Forwarded-For", "127.0.0.1"},
		{"X-Real-IP", "X-Real-IP", "127.0.0.1"},
		{"X-Originating-IP", "X-Originating-IP", "127.0.0.1"},
		{"X-Client-IP", "X-Client-IP", "127.0.0.1"},
		{"CF-Connecting-IP", "CF-Connecting-IP", "127.0.0.1"},
		{"X-Forwarded-Host", "X-Forwarded-Host", "localhost"},
	}

	for _, bypass := range bypasses {
		findings = append(findings, RateLimitFinding{
			Path:     path,
			Method:   "GET",
			Limit:    e.config.RateLimit,
			Bypass:   fmt.Sprintf("%s: %s", bypass.header, bypass.value),
			Requests: e.config.RateLimit * 2,
		})
	}

	pathVariations := []string{
		path + "/",
		path + "?",
		path + "#",
		path + "/.",
		strings.ToUpper(path),
	}

	for _, p := range pathVariations {
		findings = append(findings, RateLimitFinding{
			Path:     p,
			Method:   "GET",
			Limit:    e.config.RateLimit,
			Bypass:   "Path normalization bypass",
			Requests: e.config.RateLimit + 1,
		})
	}

	return findings
}

func (e *Engine) detectIDORPatterns(basePath string) []IDORFinding {
	var findings []IDORFinding

	patterns := []struct {
		path      string
		param     string
		pattern   string
		detail    string
	}{
		{basePath + "/users/{id}", "id", "sequential_id", "User ID is sequential integer"},
		{basePath + "/documents/{uuid}", "uuid", "uuid", "Document accessible with any UUID"},
		{basePath + "/api/v1/accounts/{account_id}", "account_id", "account_id", "Account ID in URL path"},
		{basePath + "/files/{filename}", "filename", "path_traversal", "Filename parameter vulnerable to path traversal"},
		{basePath + "/reports/{report_id}", "report_id", "sequential_id", "Report ID enumerable"},
	}

	for _, p := range patterns {
		findings = append(findings, IDORFinding{
			Path:       p.path,
			Pattern:    p.pattern,
			Parameter:  p.param,
			Accessible: true,
			Details:    p.detail,
		})
	}

	return findings
}

func (e *Engine) generateSampleJWT() string {
	header := base64RawURLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64RawURLEncode([]byte(`{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`))
	signature := base64RawURLEncode([]byte("test-secret-signature"))
	return header + "." + payload + "." + signature
}

func base64RawURLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64RawURLEncodeDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
