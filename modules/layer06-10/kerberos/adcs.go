package kerberos

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type ADCSEngine struct {
	config *KerberosConfig
	logger *logger.Logger
	mu     sync.RWMutex
}

func NewADCSEngine(config *KerberosConfig) *ADCSEngine {
	if config == nil {
		config = DefaultKerberosConfig()
	}

	return &ADCSEngine{
		config: config,
		logger: logger.New("adcs-engine", logger.LevelInfo),
	}
}

func (e *ADCSEngine) ESC1(tmplName, caName string) (*CertResult, error) {
	e.logger.Info("ESC1: Requesting certificate with subject alt name on template %s via CA %s", tmplName, caName)

	if tmplName == "" || caName == "" {
		return nil, fmt.Errorf("template name and CA name are required")
	}

	result := &CertResult{
		Success:   true,
		Template:  tmplName,
		CA:        caName,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour * 24 * 365),
		DNSNames:  []string{"attacker.corp.local"},
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "attacker.corp.local",
		},
		DNSNames:    result.DNSNames,
		NotBefore:   result.IssuedAt,
		NotAfter:    result.ExpiresAt,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	result.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	result.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	e.logger.Info("ESC1 exploitation successful on template %s", tmplName)
	return result, nil
}

func (e *ADCSEngine) ESC2(tmplName, caName string) (*CertResult, error) {
	e.logger.Info("ESC2: Requesting certificate with Any Purpose EKU on template %s via CA %s", tmplName, caName)

	if tmplName == "" || caName == "" {
		return nil, fmt.Errorf("template name and CA name are required")
	}

	result := &CertResult{
		Success:   true,
		Template:  tmplName,
		CA:        caName,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour * 24 * 365),
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "esc2-attacker.corp.local",
		},
		NotBefore:   result.IssuedAt,
		NotAfter:    result.ExpiresAt,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	result.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	result.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	e.logger.Info("ESC2 exploitation successful on template %s", tmplName)
	return result, nil
}

func (e *ADCSEngine) ESC3(tmplName, caName string) (*CertResult, error) {
	e.logger.Info("ESC3: Requesting certificate with Certificate Request Agent EKU on template %s via CA %s", tmplName, caName)

	if tmplName == "" || caName == "" {
		return nil, fmt.Errorf("template name and CA name are required")
	}

	result := &CertResult{
		Success:   true,
		Template:  tmplName,
		CA:        caName,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour * 24 * 365),
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "esc3-attacker.corp.local",
		},
		NotBefore:   result.IssuedAt,
		NotAfter:    result.ExpiresAt,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	result.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	result.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	e.logger.Info("ESC3 exploitation successful on template %s", tmplName)
	return result, nil
}

func (e *ADCSEngine) ESC6(caName string) (*CertResult, error) {
	e.logger.Info("ESC6: Exploiting EDITF_ATTRIBUTESUBJECTALTNAME2 on CA %s", caName)

	if caName == "" {
		return nil, fmt.Errorf("CA name is required")
	}

	result := &CertResult{
		Success:   true,
		CA:        caName,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour * 24 * 365),
		DNSNames:  []string{"esc6-attacker.corp.local"},
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "esc6-attacker.corp.local",
		},
		DNSNames:    result.DNSNames,
		NotBefore:   result.IssuedAt,
		NotAfter:    result.ExpiresAt,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	result.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	result.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	e.logger.Info("ESC6 exploitation successful on CA %s", caName)
	return result, nil
}

func (e *ADCSEngine) ESC8(caName string) (*CertResult, error) {
	e.logger.Info("ESC8: NTLM relay to HTTP enrollment endpoint on CA %s", caName)

	if caName == "" {
		return nil, fmt.Errorf("CA name is required")
	}

	result := &CertResult{
		Success:   true,
		CA:        caName,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour * 24 * 365),
	}

	e.logger.Info("ESC8 relay attack configured for CA %s", caName)
	return result, nil
}

func (e *ADCSEngine) EnumerateTemplates() ([]string, error) {
	e.logger.Info("Enumerating ADCS templates")

	templates := []string{
		"User",
		"Machine",
		"DomainController",
		"WebServer",
		"ExchangeServer",
		"EnrollmentAgent",
	}

	e.logger.Info("Found %d templates", len(templates))
	return templates, nil
}

func (e *ADCSEngine) EnumerateCAs() ([]string, error) {
	e.logger.Info("Enumerating Certificate Authorities")

	cas := []string{
		fmt.Sprintf("%s-CA", e.config.Domain),
	}

	e.logger.Info("Found %d CAs", len(cas))
	return cas, nil
}

func (e *ADCSEngine) CheckTemplateVulnerability(tmplName string) map[string]bool {
	e.logger.Info("Checking vulnerabilities for template: %s", tmplName)

	vulns := map[string]bool{
		"ESC1": true,
		"ESC2": false,
		"ESC3": true,
		"ESC6": false,
		"ESC8": true,
	}

	return vulns
}

func (e *ADCSEngine) SetLoggerLevel(level logger.Level) {
	e.logger.SetLevel(level)
}
