package tls13

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(TLS13Config{
		TargetHost: "example.com",
		TargetPort: 443,
		SNI:        "example.com",
	})
}

func TestDowngradeAttack(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.DowngradeAttack("TLS 1.2")
	if err != nil {
		t.Fatalf("DowngradeAttack failed: %v", err)
	}
	if !result.Success {
		t.Error("DowngradeAttack reported failure")
	}
	if result.Method != "Downgrade_Attack" {
		t.Errorf("expected method Downgrade_Attack, got %s", result.Method)
	}
	if !strings.Contains(result.Message, "TLS 1.2") {
		t.Error("should mention target version")
	}
}

func TestPaddingOracle(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.PaddingOracle("example.com")
	if err != nil {
		t.Fatalf("PaddingOracle failed: %v", err)
	}
	if !result.Success {
		t.Error("PaddingOracle reported failure")
	}
	if result.Risk != "critical" {
		t.Errorf("expected critical risk, got %s", result.Risk)
	}
}

func TestTicketReuse(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.TicketReuse("session_ticket_data_here")
	if err != nil {
		t.Fatalf("TicketReuse failed: %v", err)
	}
	if !result.Success {
		t.Error("TicketReuse reported failure")
	}
	if !strings.Contains(result.Message, "bytes") {
		t.Error("should report ticket length")
	}
}

func TestMiddlebox(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.Middlebox("example.com")
	if err != nil {
		t.Fatalf("Middlebox failed: %v", err)
	}
	if !result.Success {
		t.Error("Middlebox reported failure")
	}
	if result.Method != "Middlebox" {
		t.Errorf("expected method Middlebox, got %s", result.Method)
	}
}

func TestAnalyzeCipherSuites(t *testing.T) {
	eng := newTestEngine()
	suites := []CipherSuite{
		{ID: 1, Name: "RC4", Bits: 128},
		{ID: 2, Name: "AES_256", Bits: 256},
		{ID: 3, Name: "WEAK_CIPHER", Bits: 64},
	}
	analysis := eng.AnalyzeCipherSuites(suites)
	if analysis["RC4"] != "WEAK - Should be disabled" {
		t.Error("should mark RC4 as weak")
	}
}

func TestGetRecommendedCiphers(t *testing.T) {
	eng := newTestEngine()
	ciphers := eng.GetRecommendedCiphers()
	if len(ciphers) == 0 {
		t.Error("should return ciphers")
	}
	for _, c := range ciphers {
		if c.Grade != "A" {
			t.Errorf("expected grade A, got %s for %s", c.Grade, c.Name)
		}
	}
}

func TestGenerateJA3Fingerprint(t *testing.T) {
	eng := newTestEngine()
	fp := eng.GenerateJA3Fingerprint()
	if len(fp) == 0 {
		t.Error("fingerprint should not be empty")
	}
	if !strings.Contains(fp, "771") {
		t.Error("should start with TLS version")
	}
}

func TestDetectTLSVersion(t *testing.T) {
	eng := newTestEngine()
	tests := []struct {
		version uint16
		name    string
	}{
		{0x0304, "TLS 1.3"},
		{0x0303, "TLS 1.2"},
		{0x0301, "TLS 1.0"},
		{0x9999, "Unknown"},
	}
	for _, tt := range tests {
		got := eng.DetectTLSVersion(tt.version)
		if !strings.Contains(got, tt.name) {
			t.Errorf("DetectTLSVersion(0x%04x) = %s, want %s", tt.version, got, tt.name)
		}
	}
}
