package wireless

import (
	"testing"
)

func TestEvilTwin(t *testing.T) {
	engine := NewEngine(WirelessConfig{
		Interface: "wlan0",
	})

	result := engine.EvilTwin("OfficeWiFi")

	if result.AttackType != AttackTypeEvilTwin {
		t.Errorf("Expected EvilTwin attack type, got %v", result.AttackType)
	}
	if len(result.NetworksFound) == 0 {
		t.Error("Expected at least one network found")
	}
}

func TestDeauthAttack(t *testing.T) {
	engine := NewEngine(WirelessConfig{Interface: "wlan0"})

	result := engine.DeauthAttack("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")

	if result.DeauthResult == nil {
		t.Fatal("Expected deauth result")
	}
	if !result.DeauthResult.Disconnected {
		t.Error("Expected disconnection")
	}
	if result.DeauthResult.PacketsSent == 0 {
		t.Error("Expected packets sent > 0")
	}
}

func TestHandshakeCapture(t *testing.T) {
	engine := NewEngine(WirelessConfig{Interface: "wlan0"})

	result := engine.HandshakeCapture("00:11:22:33:44:55", "TestNetwork")

	if result.Handshake == nil {
		t.Fatal("Expected handshake")
	}
	if !result.Handshake.Complete {
		t.Error("Expected complete handshake")
	}
	if result.Handshake.BSSID != "00:11:22:33:44:55" {
		t.Errorf("Expected BSSID 00:11:22:33:44:55, got %s", result.Handshake.BSSID)
	}
}

func TestBluetoothScan(t *testing.T) {
	engine := NewEngine(WirelessConfig{BluetoothIface: "hci0"})

	result := engine.BluetoothScan()

	if len(result.BTDevices) == 0 {
		t.Error("Expected at least one Bluetooth device")
	}
	for _, dev := range result.BTDevices {
		if dev.MAC == "" {
			t.Error("Device MAC should not be empty")
		}
	}
}

func TestRFIDClone(t *testing.T) {
	engine := NewEngine(WirelessConfig{})

	result := engine.RFIDClone("04:A2:3B:C1:D5:6E:80", "Access Card")

	if len(result.RFIDCards) == 0 {
		t.Error("Expected RFID card info")
	}
	card := result.RFIDCards[0]
	if !card.Clonable {
		t.Error("Expected card to be clonable")
	}
	if len(card.Sectors) == 0 {
		t.Error("Expected sectors")
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(WirelessConfig{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
	if engine.config.Interface != "wlan0" {
		t.Error("Default interface should be wlan0")
	}
}

func TestAttackTypes(t *testing.T) {
	types := []AttackType{
		AttackTypeEvilTwin, AttackTypeDeauth, AttackTypeHandshake,
		AttackTypeWPS, AttackTypePMKID, AttackTypeKarma,
	}
	for _, at := range types {
		if at.String() == "" {
			t.Errorf("AttackType %d should have string representation", at)
		}
	}
}
