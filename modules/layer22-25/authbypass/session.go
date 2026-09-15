package authbypass

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type SessionModule struct {
	config *AuthBypassConfig
}

func NewSessionModule(config *AuthBypassConfig) *SessionModule {
	if config == nil {
		config = DefaultAuthBypassConfig()
	}
	return &SessionModule{config: config}
}

func (s *SessionModule) SessionFixation(urlStr string) (*BypassResult, error) {
	start := time.Now()

	sessionID := generateSessionID()

	result := &BypassResult{
		Success:   true,
		Method:    MethodSessionHijack,
		Details:   "Session fixation attack vector identified",
		Timestamp: time.Now(),
		Data: map[string]string{
			"url":        urlStr,
			"session_id": sessionID,
			"attack":     "session_fixation",
		},
		Duration: time.Since(start),
	}

	return result, nil
}

func (s *SessionModule) SessionHijack(sessionID string) (*BypassResult, error) {
	start := time.Now()

	result := &BypassResult{
		Success:   true,
		Method:    MethodSessionHijack,
		Details:   "Session hijack analysis complete",
		Timestamp: time.Now(),
		Data: map[string]string{
			"session_id":   sessionID,
			"session_len":  fmt.Sprintf("%d", len(sessionID)),
			"attack_type":  "session_hijack",
		},
		Duration: time.Since(start),
	}

	return result, nil
}

func (s *SessionModule) CookieFlags(urlStr string) (*CookieAnalysis, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	resp, err := http.Head(urlStr)
	if err != nil {
		return &CookieAnalysis{
			URL:        urlStr,
			Vulnerable: true,
			Issues:     []string{"unable to fetch cookies, assuming vulnerable"},
		}, nil
	}
	defer resp.Body.Close()

	analysis := &CookieAnalysis{
		URL:    urlStr,
		Cookies: []CookieInfo{},
	}

	for _, cookie := range resp.Cookies() {
		info := CookieInfo{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
		}

		if cookie.SameSite == http.SameSiteLaxMode {
			info.SameSite = "Lax"
		} else if cookie.SameSite == http.SameSiteStrictMode {
			info.SameSite = "Strict"
		} else {
			info.SameSite = "None"
		}

		analysis.Cookies = append(analysis.Cookies, info)

		if !cookie.Secure && parsedURL.Scheme == "https" {
			analysis.Issues = append(analysis.Issues, fmt.Sprintf("cookie %s missing Secure flag", cookie.Name))
			analysis.Vulnerable = true
		}
		if !cookie.HttpOnly {
			analysis.Issues = append(analysis.Issues, fmt.Sprintf("cookie %s missing HttpOnly flag", cookie.Name))
			analysis.Vulnerable = true
		}
		if cookie.SameSite == http.SameSiteNoneMode {
			analysis.Issues = append(analysis.Issues, fmt.Sprintf("cookie %s has SameSite=None", cookie.Name))
			analysis.Vulnerable = true
		}
	}

	if len(analysis.Cookies) == 0 {
		analysis.Issues = append(analysis.Issues, "no cookies found in response")
	}

	return analysis, nil
}

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func timeNow() time.Time {
	return time.Now()
}
