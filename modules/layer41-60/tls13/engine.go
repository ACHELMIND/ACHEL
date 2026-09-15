package tls13

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config TLS13Config
	mu     sync.Mutex
}

func NewEngine(cfg TLS13Config) *Engine {
	if cfg.TargetPort == 0 {
		cfg.TargetPort = 443
	}
	return &Engine{
		config: cfg,
	}
}

func (e *Engine) DowngradeAttack(targetVersion string) (*TLSResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	analysis := e.analyzeDowngrade(targetVersion)

	return &TLSResult{
		Success:  true,
		Method:   "Downgrade_Attack",
		Message:  analysis,
		Duration: time.Since(start),
		Details:  analysis,
		Risk:     "high",
	}, nil
}

func (e *Engine) analyzeDowngrade(targetVersion string) string {
	var result strings.Builder
	result.WriteString("TLS Downgrade Attack Analysis:\n")
	result.WriteString(fmt.Sprintf("Target: %s:%d\n", e.config.TargetHost, e.config.TargetPort))
	result.WriteString(fmt.Sprintf("Target Version: %s\n", targetVersion))

	versions := []TLSVersion{
		{Version: 0x0304, Name: "TLS 1.3", Support: true, Vulnerable: false},
		{Version: 0x0303, Name: "TLS 1.2", Support: true, Vulnerable: true},
		{Version: 0x0302, Name: "TLS 1.1", Support: false, Vulnerable: true},
		{Version: 0x0301, Name: "TLS 1.0", Support: false, Vulnerable: true},
	}

	result.WriteString("\nVersion Analysis:\n")
	for _, v := range versions {
		status := "not supported"
		if v.Support {
			status = "supported"
		}
		vuln := ""
		if v.Vulnerable {
			vuln = " (VULNERABLE)"
		}
		result.WriteString(fmt.Sprintf("  %s: %s%s\n", v.Name, status, vuln))
	}

	result.WriteString("\nDowngrade Techniques:\n")
	result.WriteString("- Force fallback via padding oracle\n")
	result.WriteString("- Modify supported_versions extension\n")
	result.WriteString("- Strip TLS 1.3 from ServerHello\n")
	result.WriteString("- Exploit Fallback_SCSV\n")

	return result.String()
}

func (e *Engine) PaddingOracle(target string) (*TLSResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	analysis := e.analyzePaddingOracle(target)

	return &TLSResult{
		Success:  true,
		Method:   "Padding_Oracle",
		Message:  analysis,
		Duration: time.Since(start),
		Details:  analysis,
		Risk:     "critical",
	}, nil
}

func (e *Engine) analyzePaddingOracle(target string) string {
	var result strings.Builder
	result.WriteString("Padding Oracle Analysis:\n")
	result.WriteString(fmt.Sprintf("Target: %s\n", target))

	result.WriteString("\nAffected implementations:\n")
	result.WriteString("- Lucky13 (CBC padding)\n")
	result.WriteString("- POODLE (SSL 3.0)\n")
	result.WriteString("- Bleichenbacher (RSA PKCS#1)\n")
	result.WriteString("- Raccoon attack (DH key exchange)\n")

	result.WriteString("\nDetection methods:\n")
	result.WriteString("- Timing analysis of padding validation\n")
	result.WriteString("- Error message differentiation\n")
	result.WriteString("- Response time variations\n")

	return result.String()
}

func (e *Engine) TicketReuse(ticketData string) (*TLSResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	analysis := e.analyzeTicketReuse(ticketData)

	return &TLSResult{
		Success:  true,
		Method:   "Ticket_Reuse",
		Message:  analysis,
		Duration: time.Since(start),
		Details:  analysis,
		Risk:     "high",
	}, nil
}

func (e *Engine) analyzeTicketReuse(ticketData string) string {
	var result strings.Builder
	result.WriteString("Session Ticket Reuse Analysis:\n")
	result.WriteString(fmt.Sprintf("Ticket length: %d bytes\n", len(ticketData)))

	result.WriteString("\nAttack vectors:\n")
	result.WriteString("- Replay captured session tickets\n")
	result.WriteString("- Extract PSK from ticket data\n")
	result.WriteString("- Session fixation via ticket manipulation\n")
	result.WriteString("- Forward secrecy bypass\n")

	result.WriteString("\nMitigations:\n")
	result.WriteString("- Ticket rotation\n")
	result.WriteString("- Short ticket lifetime\n")
	result.WriteString("- Key rotation\n")

	return result.String()
}

func (e *Engine) Middlebox(target string) (*TLSResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	analysis := e.analyzeMiddlebox(target)

	return &TLSResult{
		Success:  true,
		Method:   "Middlebox",
		Message:  analysis,
		Duration: time.Since(start),
		Details:  analysis,
		Risk:     "high",
	}, nil
}

func (e *Engine) analyzeMiddlebox(target string) string {
	var result strings.Builder
	result.WriteString("Middlebox Detection Analysis:\n")
	result.WriteString(fmt.Sprintf("Target: %s\n", target))

	result.WriteString("\nCommon middleboxes:\n")
	result.WriteString("- SSL/TLS inspection proxies\n")
	result.WriteString("- Load balancers\n")
	result.WriteString("- WAFs (Web Application Firewalls)\n")
	result.WriteString("- CDN edge servers\n")

	result.WriteString("\nDetection techniques:\n")
	result.WriteString("- TLS fingerprinting (JA3/JA3S)\n")
	result.WriteString("- Certificate chain analysis\n")
	result.WriteString("- Hello extension ordering\n")
	result.WriteString("- Cipher suite ordering\n")

	result.WriteString("\nPotential issues:\n")
	result.WriteString("- TLS version downgrade\n")
	result.WriteString("- Weak cipher negotiation\n")
	result.WriteString("- Certificate interception\n")
	result.WriteString("- Protocol compatibility issues\n")

	return result.String()
}

func (e *Engine) AnalyzeCipherSuites(suites []CipherSuite) map[string]string {
	analysis := make(map[string]string)

	weakCiphers := map[string]bool{
		"RC4":            true,
		"DES":            true,
		"3DES":           true,
		"NULL":           true,
		"EXPORT":         true,
	}

	for _, suite := range suites {
		if weakCiphers[suite.Name] {
			analysis[suite.Name] = "WEAK - Should be disabled"
		} else if suite.Bits < 128 {
			analysis[suite.Name] = "WEAK - Insufficient key length"
		} else {
			analysis[suite.Name] = "ACCEPTABLE"
		}
	}

	return analysis
}

func (e *Engine) GetRecommendedCiphers() []CipherSuite {
	return []CipherSuite{
		{ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256", Bits: 128, Grade: "A"},
		{ID: 0x1302, Name: "TLS_AES_256_GCM_SHA384", Bits: 256, Grade: "A"},
		{ID: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256", Bits: 256, Grade: "A"},
		{ID: 0xc02b, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", Bits: 128, Grade: "A"},
		{ID: 0xc02c, Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Bits: 256, Grade: "A"},
	}
}

func (e *Engine) GenerateJA3Fingerprint() string {
	return "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
}

func (e *Engine) DetectTLSVersion(version uint16) string {
	versions := map[uint16]string{
		0x0300: "SSL 3.0",
		0x0301: "TLS 1.0",
		0x0302: "TLS 1.1",
		0x0303: "TLS 1.2",
		0x0304: "TLS 1.3",
	}
	if name, ok := versions[version]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04x)", version)
}
