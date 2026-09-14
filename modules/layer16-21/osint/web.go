package osint

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/angel-platform/angel/pkg/logger"
)

type WebRecon struct {
	config *OSINTConfig
	log    *logger.Logger
	mu     sync.RWMutex
	client *http.Client
}

func NewWebRecon(config *OSINTConfig) *WebRecon {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &WebRecon{
		config: config,
		log:    logger.New("web-recon", logger.LevelInfo),
		client: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if !config.FollowRedirects {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (w *WebRecon) TechFingerprint(url string) (*TechStack, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.log.Info("Tech fingerprinting: %s", url)

	resp, err := w.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}

	bodyStr := string(body)
	headers := resp.Header

	stack := &TechStack{
		Meta: make(map[string]string),
	}

	if server := headers.Get("Server"); server != "" {
		stack.Server = server
	}

	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		stack.Languages = append(stack.Languages, poweredBy)
	}

	patterns := map[string]string{
		"WordPress":    "wp-content",
		"Drupal":       "drupal",
		"Joomla":       "joomla",
		"React":        "react",
		"Vue.js":       "vue",
		"Angular":      "angular",
		"jQuery":       "jquery",
		"Bootstrap":    "bootstrap",
		"Laravel":      "laravel",
		"Django":       "django",
		"Flask":        "flask",
		"Express":      "express",
		"Next.js":      "next",
		"Nuxt.js":      "nuxt",
		"Gatsby":       "gatsby",
		"Shopify":      "shopify",
		"Wix":          "wix",
		"Squarespace":  "squarespace",
		"Google Analytics": "google-analytics",
		"Google Tag Manager": "googletagmanager",
		"Cloudflare":   "cloudflare",
		"AWS":          "amazonaws",
		"Vercel":       "vercel",
	}

	for tech, marker := range patterns {
		if strings.Contains(bodyStr, marker) {
			switch {
			case tech == "React" || tech == "Vue.js" || tech == "Angular" || tech == "jQuery" || tech == "Bootstrap":
				stack.JS = append(stack.JS, tech)
			case tech == "Google Analytics" || tech == "Google Tag Manager":
				stack.Analytics = append(stack.Analytics, tech)
			default:
				stack.Frameworks = append(stack.Frameworks, tech)
			}
		}
	}

	w.log.Info("Tech fingerprint completed: %s", url)
	return stack, nil
}

func (w *WebRecon) WAFDetect(url string) (*WAFInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.log.Info("WAF detection: %s", url)

	resp, err := w.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	headers := resp.Header
	waf := &WAFInfo{}

	wafSignatures := map[string]string{
		"Cloudflare":  "cf-ray",
		"AWS WAF":     "x-amzn-requestid",
		"Akamai":      "x-akamai-transformed",
		"Sucuri":      "x-sucuri-id",
		"Wordfence":   "wordfence",
		"ModSecurity": "mod_security",
		"Imperva":     "x-iinfo",
		"F5":          "x-wa-info",
	}

	for name, header := range wafSignatures {
		if _, ok := headers[http.CanonicalHeaderKey(header)]; ok {
			waf.Detected = true
			waf.Name = name
			waf.Vendor = name
			break
		}
	}

	if !waf.Detected {
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			bodyStr := string(body)
			if strings.Contains(bodyStr, "Access Denied") || strings.Contains(bodyStr, "blocked") {
				waf.Detected = true
				waf.Name = "Unknown WAF"
			}
		}
	}

	w.log.Info("WAF detection completed: %s (detected: %v)", url, waf.Detected)
	return waf, nil
}

func (w *WebRecon) SSLInspect(domain string) (*CertInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.log.Info("SSL inspection: %s", domain)

	addr := fmt.Sprintf("%s:443", domain)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	cert := certs[0]
	info := &CertInfo{
		Issuer:     cert.Issuer.CommonName,
		Subject:    cert.Subject.CommonName,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		DNSNames:   cert.DNSNames,
		Serial:     cert.SerialNumber.String(),
		KeySize:    256,
		SelfSigned: cert.Issuer.CommonName == cert.Subject.CommonName,
	}

	w.log.Info("SSL inspection completed: %s", domain)
	return info, nil
}

func (w *WebRecon) RobotsParse(url string) ([]string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.log.Info("Parsing robots.txt: %s", url)

	robotsURL := url
	if !strings.HasSuffix(url, "robots.txt") {
		robotsURL = strings.TrimSuffix(url, "/") + "/robots.txt"
	}

	resp, err := w.client.Get(robotsURL)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("robots.txt not found (status: %d)", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}

	rules := make([]string, 0)
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Disallow:") || strings.HasPrefix(line, "Allow:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				rules = append(rules, strings.TrimSpace(parts[1]))
			}
		}
	}

	w.log.Info("Robots.txt parsed: %d rules found", len(rules))
	return rules, nil
}

func (w *WebRecon) ReconWeb(target string) (*WebResult, error) {
	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + target
	}

	result := &WebResult{
		URL: url,
	}

	techStack, err := w.TechFingerprint(url)
	if err == nil {
		result.TechStack = techStack
	}

	waf, err := w.WAFDetect(url)
	if err == nil {
		result.WAF = waf
	}

	host := strings.TrimPrefix(url, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]

	cert, err := w.SSLInspect(host)
	if err == nil {
		result.Cert = cert
	}

	robots, err := w.RobotsParse(url)
	if err == nil {
		result.Robots = robots
	}

	return result, nil
}

func (w *WebRecon) GetHeaders(url string) (map[string]string, error) {
	resp, err := w.client.Head(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, "; ")
	}
	return headers, nil
}

func (w *WebRecon) CheckWAF(url string) bool {
	waf, err := w.WAFDetect(url)
	if err != nil {
		return false
	}
	return waf.Detected
}

func extractMetaTags(body string) map[string]string {
	meta := make(map[string]string)
	re := regexp.MustCompile(`<meta\s+[^>]*name=["']([^"']+)["'][^>]*content=["']([^"']+)["'][^>]*>`)
	matches := re.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			meta[match[1]] = match[2]
		}
	}
	return meta
}
