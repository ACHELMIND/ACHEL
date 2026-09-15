package physical

import (
	"testing"
)

func TestUSBDrop(t *testing.T) {
	engine := NewEngine(PhysicalConfig{})

	result := engine.USBDrop(3)

	if len(result.USBDrops) != 3 {
		t.Errorf("Expected 3 USB drops, got %d", len(result.USBDrops))
	}
	for _, drop := range result.USBDrops {
		if drop.USBType != USBAttackTypeHID {
			t.Error("Expected HID attack type")
		}
		if !drop.PickedUp {
			t.Error("Expected picked up")
		}
	}
}

func TestBadgeClone(t *testing.T) {
	engine := NewEngine(PhysicalConfig{})

	result := engine.BadgeClone("04:A2:3B:C1:D5:6E:80")

	if len(result.BadgeClones) == 0 {
		t.Error("Expected badge clones")
	}
	for _, clone := range result.BadgeClones {
		if clone.OriginalUID == "" {
			t.Error("Original UID should not be empty")
		}
		if !clone.Success {
			t.Error("Expected clone success")
		}
	}
}

func TestLockPicking(t *testing.T) {
	engine := NewEngine(PhysicalConfig{})

	result := engine.LockPicking("pin_tumbler")

	if len(result.LockResults) == 0 {
		t.Error("Expected lock results")
	}
	pickedCount := 0
	for _, lr := range result.LockResults {
		if lr.Success {
			pickedCount++
		}
	}
	if pickedCount == 0 {
		t.Error("Expected at least one successful pick")
	}
}

func TestNetworkTap(t *testing.T) {
	engine := NewEngine(PhysicalConfig{})

	result := engine.NetworkTap("Server Room")

	if len(result.NetworkTaps) == 0 {
		t.Error("Expected network taps")
	}
	for _, tap := range result.NetworkTaps {
		if tap.Location != "Server Room" {
			t.Errorf("Expected location 'Server Room', got %s", tap.Location)
		}
		if !tap.Active {
			t.Error("Expected active tap")
		}
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(PhysicalConfig{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
}

func TestUSBAttackTypes(t *testing.T) {
	types := []USBAttackType{
		USBAttackTypeHID, USBAttackTypeStorage, USBAttackTypeNetwork,
		USBAttackTypeBadUSB, USBAttackTypeRubberDucky, USBAttackTypeOMG,
	}
	for _, ut := range types {
		if ut.String() == "" {
			t.Errorf("USBAttackType %d should have string", ut)
		}
	}
}
