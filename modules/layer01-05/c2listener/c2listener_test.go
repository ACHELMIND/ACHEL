package c2listener

import (
	"testing"
)

func TestNewC2Listener(t *testing.T) {
	l := NewC2Listener("127.0.0.1", 8080)
	if l == nil {
		t.Fatal("expected non-nil C2Listener")
	}
	if l.addr != "127.0.0.1" {
		t.Errorf("expected addr 127.0.0.1, got %s", l.addr)
	}
	if l.port != 8080 {
		t.Errorf("expected port 8080, got %d", l.port)
	}
}

func TestC2Listener_StopBeforeStart(t *testing.T) {
	l := NewC2Listener("127.0.0.1", 0)
	l.Stop()
}
