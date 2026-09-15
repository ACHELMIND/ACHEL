package dnssec

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(DNSSECConfig{
		Domain:    "example.com",
		DNSServer: "8.8.8.8",
		Timeout:   5000000000,
	})
}

func TestNSECWalking(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.NSECWalking("example.com")
	if err != nil {
		t.Fatalf("NSECWalking failed: %v", err)
	}
	if !result.Success {
		t.Error("NSECWalking reported failure")
	}
	if result.Method != "NSEC_Walking" {
		t.Errorf("expected method NSEC_Walking, got %s", result.Method)
	}
	if result.Count == 0 {
		t.Error("should find at least one record")
	}
}

func TestNSECWalkingFindsSubdomains(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.NSECWalking("example.com")
	if err != nil {
		t.Fatalf("NSECWalking failed: %v", err)
	}
	hasWWW := false
	for _, r := range result.Records {
		if strings.Contains(r, "www") {
			hasWWW = true
		}
	}
	if !hasWWW {
		t.Error("should discover www subdomain")
	}
}

func TestKeyRollingExploit(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.KeyRollingExploit("example.com", 8, 13)
	if err != nil {
		t.Fatalf("KeyRollingExploit failed: %v", err)
	}
	if !result.Success {
		t.Error("KeyRollingExploit reported failure")
	}
	if result.Method != "Key_Rolling_Exploit" {
		t.Errorf("expected method Key_Rolling_Exploit, got %s", result.Method)
	}
}

func TestSignatureForge(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.SignatureForge("example.com", 12345)
	if err != nil {
		t.Fatalf("SignatureForge failed: %v", err)
	}
	if !result.Success {
		t.Error("SignatureForge reported failure")
	}
	if !strings.Contains(result.Records[0], "FORGED") {
		t.Error("should contain forged signature")
	}
}

func TestZoneWalk(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.ZoneWalk("example.com")
	if err != nil {
		t.Fatalf("ZoneWalk failed: %v", err)
	}
	if !result.Success {
		t.Error("ZoneWalk reported failure")
	}
	if result.Count == 0 {
		t.Error("should find at least one record")
	}
}

func TestZoneWalkSubdomains(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.ZoneWalk("example.com")
	if err != nil {
		t.Fatalf("ZoneWalk failed: %v", err)
	}
	if len(result.Records) < 5 {
		t.Errorf("expected at least 5 records, got %d", len(result.Records))
	}
}

func TestAnalyzeDNSSEC(t *testing.T) {
	eng := newTestEngine()
	analysis := eng.AnalyzeDNSSEC("example.com")
	if analysis["domain"] != "example.com" {
		t.Error("wrong domain in analysis")
	}
	signed, ok := analysis["signed"].(bool)
	if !ok || !signed {
		t.Error("should report signed")
	}
}

func TestBuildNSEC3Hash(t *testing.T) {
	eng := newTestEngine()
	hash := eng.BuildNSEC3Hash("example.com", "salt", 10)
	if len(hash) == 0 {
		t.Error("hash should not be empty")
	}
}

func TestEnumerateZone(t *testing.T) {
	eng := newTestEngine()
	records := eng.EnumerateZone("example.com")
	if len(records) == 0 {
		t.Error("should return records")
	}
	hasA := false
	hasMX := false
	for _, r := range records {
		if strings.Contains(r, " A ") {
			hasA = true
		}
		if strings.Contains(r, " MX ") {
			hasMX = true
		}
	}
	if !hasA {
		t.Error("should include A record")
	}
	if !hasMX {
		t.Error("should include MX record")
	}
}

func TestSimulateNSECRecord(t *testing.T) {
	eng := newTestEngine()
	nsec := eng.simulateNSECRecord("*.example.com", "example.com")
	if nsec.NextDomain == "" {
		t.Error("next domain should not be empty")
	}
	if len(nsec.TypeBitmaps) == 0 {
		t.Error("type bitmaps should not be empty")
	}
}
