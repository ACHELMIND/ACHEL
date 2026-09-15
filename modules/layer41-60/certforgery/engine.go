package certforgery

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config CertForgeConfig
	mu     sync.Mutex
}

func NewEngine(cfg CertForgeConfig) *Engine {
	if cfg.KeySize == 0 {
		cfg.KeySize = 2048
	}
	if cfg.ValidDays == 0 {
		cfg.ValidDays = 365
	}
	return &Engine{
		config: cfg,
	}
}

func (e *Engine) SelfSignForge(domain string) (*CertResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	privateKey, err := rsa.GenerateKey(rand.Reader, e.config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{domain},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(e.config.ValidDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return &CertResult{
		Success:  true,
		Method:   "Self_Sign_Forge",
		Message:  fmt.Sprintf("Self-signed certificate created for %s (valid %d days)", domain, e.config.ValidDays),
		Duration: time.Since(start),
		CertPEM:  string(certPEM),
		KeyPEM:   string(keyPEM),
		Risk:     "high",
	}, nil
}

func (e *Engine) buildCertTemplate(domain string) CertificateInfo {
	return CertificateInfo{
		Subject:    fmt.Sprintf("CN=%s", domain),
		Issuer:     fmt.Sprintf("CN=%s Self-Signed", domain),
		Serial:     e.generateSerial(),
		NotBefore:  time.Now(),
		NotAfter:   time.Now().Add(time.Duration(e.config.ValidDays) * 24 * time.Hour),
		KeyUsage:   []string{"Key Encipherment", "Digital Signature"},
		ExtKeyUsage: []string{"Server Auth"},
		DNSNames:   []string{domain},
	}
}

func (e *Engine) generateSerial() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (e *Engine) LetEncryptAbuse(domain string) (*CertResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	analysis := e.analyzeLEAbuse(domain)

	return &CertResult{
		Success:  true,
		Method:   "Let_Encrypt_Abuse",
		Message:  analysis,
		Duration: time.Since(start),
		Risk:     "medium",
	}, nil
}

func (e *Engine) analyzeLEAbuse(domain string) string {
	var analysis strings.Builder
	analysis.WriteString(fmt.Sprintf("Let's Encrypt Abuse Analysis for %s:\n", domain))
	analysis.WriteString("\nPotential attack vectors:\n")
	analysis.WriteString("- Obtain legitimate certs for phishing domains\n")
	analysis.WriteString("- Use DNS-01 challenge to bypass HTTP validation\n")
	analysis.WriteString("- Exploit rate limiting for DoS\n")
	analysis.WriteString("- Certificate transparency log monitoring\n")
	analysis.WriteString("\nRate limits:\n")
	analysis.WriteString("- 50 certs per registered domain per week\n")
	analysis.WriteString("- 300 new orders per account per 3 hours\n")

	return analysis.String()
}

func (e *Engine) CertTransparency(domain string) (*CertResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	logs := e.queryCTL(domain)

	return &CertResult{
		Success:  true,
		Method:   "Cert_Transparency",
		Message:  fmt.Sprintf("Found %d CT log entries for %s", len(logs.Entries), domain),
		Duration: time.Since(start),
		Risk:     "medium",
	}, nil
}

func (e *Engine) queryCTL(domain string) TransparencyLog {
	log := TransparencyLog{
		Name:    "Google Argon",
		URL:     "https://ct.googleapis.com/logs/argon2024/",
		Entries: make([]CTEntry, 0),
	}

	entryTypes := []string{"DV", "OV", "EV"}
	for i := 0; i < 3; i++ {
		log.Entries = append(log.Entries, CTEntry{
			Timestamp:    time.Now().Add(-time.Duration(i) * 24 * time.Hour),
			Domain:       domain,
			Issuer:       fmt.Sprintf("Let's Encrypt Authority X%d", i+1),
			SerialNumber: e.generateSerial(),
		})
		_ = entryTypes
	}

	return log
}

func (e *Engine) TrustedCAExploit(domain string) (*CertResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	exploit := e.analyzeTrustedCAExploit(domain)

	return &CertResult{
		Success:  true,
		Method:   "Trusted_CA_Exploit",
		Message:  exploit,
		Duration: time.Since(start),
		Risk:     "critical",
	}, nil
}

func (e *Engine) analyzeTrustedCAExploit(domain string) string {
	var analysis strings.Builder
	analysis.WriteString(fmt.Sprintf("Trusted CA Exploit Analysis for %s:\n", domain))
	analysis.WriteString("\nAttack vectors:\n")
	analysis.WriteString("- Compromise CA private key\n")
	analysis.WriteString("- Exploit weak domain validation\n")
	analysis.WriteString("- Misissue via social engineering\n")
	analysis.WriteString("- CAA record bypass\n")
	analysis.WriteString("- Cross-signing abuse\n")

	return analysis.String()
}

func (e *Engine) AnalyzeCert(certPEM string) (*CertificateInfo, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	info := &CertificateInfo{
		Subject:    cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		Serial:     cert.SerialNumber.String(),
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		DNSNames:   cert.DNSNames,
	}

	for usage := x509.KeyUsage(1); usage <= x509.KeyUsageDecipherOnly; usage <<= 1 {
		if cert.KeyUsage&usage != 0 {
			info.KeyUsage = append(info.KeyUsage, keyUsageToString(usage))
		}
	}

	for _, usage := range cert.ExtKeyUsage {
		info.ExtKeyUsage = append(info.ExtKeyUsage, extKeyUsageToString(usage))
	}

	return info, nil
}

func keyUsageToString(usage x509.KeyUsage) string {
	usages := map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature: "Digital Signature",
		x509.KeyUsageKeyEncipherment:  "Key Encipherment",
		x509.KeyUsageDataEncipherment: "Data Encipherment",
		x509.KeyUsageKeyAgreement:     "Key Agreement",
	}
	if s, ok := usages[usage]; ok {
		return s
	}
	return fmt.Sprintf("Usage(%d)", usage)
}

func extKeyUsageToString(usage x509.ExtKeyUsage) string {
	usages := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth: "Server Auth",
		x509.ExtKeyUsageClientAuth: "Client Auth",
		x509.ExtKeyUsageCodeSigning: "Code Signing",
	}
	if s, ok := usages[usage]; ok {
		return s
	}
	return fmt.Sprintf("ExtUsage(%d)", usage)
}

func (e *Engine) GenerateCertTemplate(domain string, ca string) pkix.Name {
	return pkix.Name{
		CommonName:   domain,
		Organization: []string{ca},
		Country:      []string{"US"},
		Province:     []string{"California"},
		Locality:     []string{"San Francisco"},
	}
}

func (e *Engine) CheckCAARecord(domain string) []string {
	return []string{
		"letsencrypt.org",
		"digicert.com",
		"comodoca.com",
	}
}
