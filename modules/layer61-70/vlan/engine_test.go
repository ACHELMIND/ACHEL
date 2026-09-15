package vlan

import "testing"

func TestDoubleTagging(t *testing.T) {
	config := VLANConfig{
		Interface:     "eth0",
		SourceVLAN:    100,
		TargetVLAN:    1,
		AttackType:    VLANAttackDoubleTagging,
		PacketsToSend: 100,
	}
	engine := NewEngine(config)
	result := engine.DoubleTagging()
	if result.Attack != VLANAttackDoubleTagging {
		t.Errorf("expected DoubleTagging, got %d", result.Attack)
	}
	if result.PacketsSent != 100 {
		t.Errorf("expected 100 packets, got %d", result.PacketsSent)
	}
	if len(result.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(result.Tags))
	}
}

func TestSwitchSpoofing(t *testing.T) {
	config := VLANConfig{
		Interface:  "eth0",
		MACSource:  "aa:bb:cc:dd:ee:ff",
		AttackType: VLANAttackSwitchSpoofing,
	}
	engine := NewEngine(config)
	result := engine.SwitchSpoofing()
	if result.Attack != VLANAttackSwitchSpoofing {
		t.Errorf("expected SwitchSpoofing, got %d", result.Attack)
	}
	if !result.Success {
		t.Error("expected success")
	}
}

func TestVLANGrafting(t *testing.T) {
	config := VLANConfig{
		Interface:  "eth0",
		TargetVLAN: 50,
		AttackType: VLANAttackVLANGrafting,
	}
	engine := NewEngine(config)
	result := engine.VLANGrafting()
	if result.Attack != VLANAttackVLANGrafting {
		t.Errorf("expected VLANGrafting, got %d", result.Attack)
	}
	if result.FrameHex == "" {
		t.Error("expected non-empty frame hex")
	}
}

func TestTrunkPort(t *testing.T) {
	config := VLANConfig{
		Interface:  "eth0",
		AttackType: VLANAttackTrunkNegotiation,
	}
	engine := NewEngine(config)
	result := engine.TrunkPort()
	if result.Attack != VLANAttackTrunkNegotiation {
		t.Errorf("expected TrunkNegotiation, got %d", result.Attack)
	}
	if len(result.Tags) == 0 {
		t.Error("expected non-empty tags")
	}
}
