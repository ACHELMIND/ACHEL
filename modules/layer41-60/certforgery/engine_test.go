package certforgery

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(CertForgeConfig{
		Domain:    "example.com",
		CA:        "Self-Signed",
		KeyType:   "RSA",
		KeySize:   2048,
		ValidDays: 365,
	})
}

func TestSelfSignForge(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.SelfSignForge("example.com")
	if err != nil {
		t.Fatalf("SelfSignForge failed: %v", err)
	}
	if !result.Success {
		t.Error("SelfSignForge reported failure")
	}
	if result.Method != "Self_Sign_Forge" {
		t.Errorf("expected method Self_Sign_Forge, got %s", result.Method)
	}
	if len(result.CertPEM) == 0 {
		t.Error("cert PEM is empty")
	}
	if len(result.KeyPEM) == 0 {
		t.Error("key PEM is empty")
	}
}

func TestSelfSignForgeContainsDomain(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.SelfSignForge("evil.com")
	if err != nil {
		t.Fatalf("SelfSignForge failed: %v", err)
	}
	if !strings.Contains(result.CertPEM, "CERTIFICATE") {
		t.Error("should contain CERTIFICATE header")
	}
}

func TestLetEncryptAbuse(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.LetEncryptAbuse("phishing.com")
	if err != nil {
		t.Fatalf("LetEncryptAbuse failed: %v", err)
	}
	if !result.Success {
		t.Error("LetEncryptAbuse reported failure")
	}
	if !strings.Contains(result.Message, "Let's Encrypt") {
		t.Error("should mention Let's Encrypt")
	}
}

func TestCertTransparency(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CertTransparency("example.com")
	if err != nil {
		t.Fatalf("CertTransparency failed: %v", err)
	}
	if !result.Success {
		t.Error("CertTransparency reported failure")
	}
	if result.Method != "Cert_Transparency" {
		t.Errorf("expected method Cert_Transparency, got %s", result.Method)
	}
}

func TestTrustedCAExploit(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.TrustedCAExploit("target.com")
	if err != nil {
		t.Fatalf("TrustedCAExploit failed: %v", err)
	}
	if !result.Success {
		t.Error("TrustedCAExploit reported failure")
	}
	if result.Risk != "critical" {
		t.Errorf("expected critical risk, got %s", result.Risk)
	}
}

func TestAnalyzeCert(t *testing.T) {
	eng := newTestEngine()
	certResult, err := eng.SelfSignForge("test.com")
	if err != nil {
		t.Fatalf("SelfSignForge failed: %v", err)
	}

	info, err := eng.AnalyzeCert(certResult.CertPEM)
	if err != nil {
		t.Fatalf("AnalyzeCert failed: %v", err)
	}
	if info.Subject != "test.com" {
		t.Errorf("expected subject test.com, got %s", info.Subject)
	}
}

func TestAnalyzeCertInvalid(t *testing.T) {
	eng := newTestEngine()
	_, err := eng.AnalyzeCert("not-a-cert")
	if err == nil {
		t.Error("expected error for invalid cert")
	}
}

func TestGenerateCertTemplate(t *testing.T) {
	eng := newTestEngine()
	template := eng.GenerateCertTemplate("example.com", "MyCA")
	if template.CommonName != "example.com" {
		t.Errorf("expected CN example.com, got %s", template.CommonName)
	}
	if len(template.Organization) == 0 || template.Organization[0] != "MyCA" {
		t.Error("expected org MyCA")
	}
}

func TestCheckCAARecord(t *testing.T) {
	eng := newTestEngine()
	records := eng.CheckCAARecord("example.com")
	if len(records) == 0 {
		t.Error("should return CAA records")
	}
}
