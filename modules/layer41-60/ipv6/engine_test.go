package ipv6

import (
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(IPv6Config{
		Target:    "fe80::1",
		Interface: "eth0",
		SourceIP:  "fe80::2",
		PrefixLen: 64,
	})
}

func TestRASpoof(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.RASpoof("2001:db8::", 64, []string{"2001:db8::1"})
	if err != nil {
		t.Fatalf("RASpoof failed: %v", err)
	}
	if !result.Success {
		t.Error("RASpoof reported failure")
	}
	if result.Method != "RA_Spoof" {
		t.Errorf("expected method RA_Spoof, got %s", result.Method)
	}
	if result.Packets != 1 {
		t.Errorf("expected 1 packet, got %d", result.Packets)
	}
}

func TestRASpoofInvalidPrefix(t *testing.T) {
	eng := newTestEngine()
	_, err := eng.RASpoof("not-an-ip", 64, nil)
	if err == nil {
		t.Error("expected error for invalid prefix")
	}
}

func TestNSFlood(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.NSFlood("fe80::3", 10)
	if err != nil {
		t.Fatalf("NSFlood failed: %v", err)
	}
	if !result.Success {
		t.Error("NSFlood reported failure")
	}
	if result.Packets != 10 {
		t.Errorf("expected 10 packets, got %d", result.Packets)
	}
}

func TestNSFloodInvalidTarget(t *testing.T) {
	eng := newTestEngine()
	_, err := eng.NSFlood("invalid", 10)
	if err == nil {
		t.Error("expected error for invalid target")
	}
}

func TestDADAttack(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.DADAttack("fe80::4", 5)
	if err != nil {
		t.Fatalf("DADAttack failed: %v", err)
	}
	if !result.Success {
		t.Error("DADAttack reported failure")
	}
	if result.Packets != 5 {
		t.Errorf("expected 5 packets, got %d", result.Packets)
	}
}

func TestDNSv6Spoof(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.DNSv6Spoof("example.com", "2001:db8::99")
	if err != nil {
		t.Fatalf("DNSv6Spoof failed: %v", err)
	}
	if !result.Success {
		t.Error("DNSv6Spoof reported failure")
	}
	if result.Method != "DNSv6_Spoof" {
		t.Errorf("expected method DNSv6_Spoof, got %s", result.Method)
	}
}

func TestDNSv6SpoofInvalidIP(t *testing.T) {
	eng := newTestEngine()
	_, err := eng.DNSv6Spoof("example.com", "bad-ip")
	if err == nil {
		t.Error("expected error for invalid IPv6")
	}
}

func TestTunnelAbuse(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.TunnelAbuse("6to4", "192.88.99.1")
	if err != nil {
		t.Fatalf("TunnelAbuse failed: %v", err)
	}
	if !result.Success {
		t.Error("TunnelAbuse reported failure")
	}
	if result.Method != "Tunnel_Abuse" {
		t.Errorf("expected method Tunnel_Abuse, got %s", result.Method)
	}
}

func TestTunnelAbuseInvalidType(t *testing.T) {
	eng := newTestEngine()
	_, err := eng.TunnelAbuse("invalid-tunnel", "1.2.3.4")
	if err == nil {
		t.Error("expected error for invalid tunnel type")
	}
}

func TestBuildRAPacket(t *testing.T) {
	eng := newTestEngine()
	pkt := eng.buildRAPacket("2001:db8::", 64, []string{"2001:db8::1"})
	if len(pkt) < 14 {
		t.Errorf("RA packet too short: %d bytes", len(pkt))
	}
	if pkt[0] != 0x86 {
		t.Errorf("expected ICMPv6 RA type 0x86, got 0x%02x", pkt[0])
	}
}

func TestBuildNSPacket(t *testing.T) {
	eng := newTestEngine()
	pkt := eng.buildNSPacket("fe80::1")
	if len(pkt) < 20 {
		t.Errorf("NS packet too short: %d bytes", len(pkt))
	}
	if pkt[0] != 0x87 {
		t.Errorf("expected ICMPv6 NS type 0x87, got 0x%02x", pkt[0])
	}
}

func TestIsValidIPv6(t *testing.T) {
	eng := newTestEngine()
	tests := []struct {
		addr   string
		expect bool
	}{
		{"fe80::1", true},
		{"2001:db8::1", true},
		{"::1", true},
		{"192.168.1.1", false},
		{"invalid", false},
		{"", false},
	}
	for _, tt := range tests {
		got := eng.isValidIPv6(tt.addr)
		if got != tt.expect {
			t.Errorf("isValidIPv6(%q) = %v, want %v", tt.addr, got, tt.expect)
		}
	}
}

func TestNSFloodDefaultCount(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.NSFlood("fe80::5", 0)
	if err != nil {
		t.Fatalf("NSFlood failed: %v", err)
	}
	if result.Packets != 100 {
		t.Errorf("expected default 100 packets, got %d", result.Packets)
	}
}

func TestTunnelAbuseIsatap(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.TunnelAbuse("isatap", "10.0.0.1")
	if err != nil {
		t.Fatalf("TunnelAbuse isatap failed: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	b := generateRandomBytes(16)
	if len(b) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(b))
	}
}

func TestGenerateRandomHex(t *testing.T) {
	h := generateRandomHex(8)
	if len(h) != 16 {
		t.Errorf("expected 16 hex chars, got %d", len(h))
	}
}
