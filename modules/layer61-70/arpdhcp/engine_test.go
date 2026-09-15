package arpdhcp

import "testing"

func TestARPSpoof(t *testing.T) {
	config := ARPDHCPConfig{
		Interface: "eth0",
		LocalIP:   "192.168.1.50",
		LocalMAC:  "aa:bb:cc:dd:ee:ff",
		TargetIPs: []string{"192.168.1.100", "192.168.1.101"},
		GatewayIP: "192.168.1.1",
	}
	engine := NewEngine(config)
	result := engine.ARPSpoof()
	if result.Attack != ARPAttackSpoof {
		t.Errorf("expected Spoof attack, got %d", result.Attack)
	}
	if result.TargetsPoisoned != 2 {
		t.Errorf("expected 2 poisoned, got %d", result.TargetsPoisoned)
	}
}

func TestARPStorm(t *testing.T) {
	config := ARPDHCPConfig{
		Interface: "eth0",
		LocalMAC:  "aa:bb:cc:dd:ee:ff",
		NumSpoof:  256,
	}
	engine := NewEngine(config)
	result := engine.ARPStorm()
	if result.Attack != ARPAttackStorm {
		t.Errorf("expected Storm attack, got %d", result.Attack)
	}
	if result.PacketsSent != 256 {
		t.Errorf("expected 256 packets, got %d", result.PacketsSent)
	}
}

func TestDHCPRogue(t *testing.T) {
	config := ARPDHCPConfig{
		Interface: "eth0",
		LocalMAC:  "aa:bb:cc:dd:ee:ff",
		DHCPServer: &DHCPServer{
			IP:      "192.168.1.200",
			MAC:     "aa:bb:cc:dd:ee:ff",
			Gateway: "192.168.1.200",
			DNS:     "8.8.8.8",
			Lease:   86400,
			Range:   "192.168.1.100-192.168.1.200",
		},
	}
	engine := NewEngine(config)
	result := engine.DHCPRogue()
	if !result.RogueDHCP {
		t.Error("expected rogue DHCP")
	}
	if !result.Success {
		t.Error("expected success")
	}
}

func TestDHCPEhaustion(t *testing.T) {
	config := ARPDHCPConfig{
		Interface: "eth0",
		LocalMAC:  "aa:bb:cc:dd:ee:ff",
		NumSpoof:  255,
	}
	engine := NewEngine(config)
	result := engine.DHCPEhaustion()
	if result.PacketsSent != 255 {
		t.Errorf("expected 255 packets, got %d", result.PacketsSent)
	}
}
