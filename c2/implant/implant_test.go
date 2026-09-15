package implant

import (
	"testing"
)

func TestImplantNew(t *testing.T) {
	implant := NewImplant(nil)
	if implant == nil {
		t.Fatal("expected non-nil implant")
	}
	if implant.config.ServerURL != "https://teamserver.example.com" {
		t.Errorf("expected default server URL")
	}
}

func TestImplantStop(t *testing.T) {
	implant := NewImplant(nil)
	implant.running = true
	implant.Stop()
	if implant.running {
		t.Error("expected implant to be stopped")
	}
}

func TestImplantSessionID(t *testing.T) {
	implant := NewImplant(nil)
	sessionID := implant.generateSessionID()
	if sessionID == "" {
		t.Error("expected non-empty session ID")
	}
}
