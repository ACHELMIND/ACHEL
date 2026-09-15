package c2listener

import (
	"testing"
)

func TestNewC2Channel(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{
		Protocol: "https",
		Addr:     "127.0.0.1",
		Port:     443,
		Encrypted: true,
		MaxRetries: 3,
	})
	if ch == nil {
		t.Fatal("expected non-nil C2Channel")
	}
	if ch.protocol != "https" {
		t.Errorf("expected protocol https, got %s", ch.protocol)
	}
	if ch.maxRetries != 3 {
		t.Errorf("expected maxRetries 3, got %d", ch.maxRetries)
	}
}

func TestNewC2Channel_DefaultRetries(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{})
	if ch.maxRetries != 5 {
		t.Errorf("expected default maxRetries 5, got %d", ch.maxRetries)
	}
}

func TestC2Channel_GetID(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{})
	id := ch.GetID()
	if id == "" {
		t.Error("expected non-empty ID (auto-generated)")
	}
}

func TestC2Channel_GetProtocol(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{Protocol: "dns"})
	if ch.GetProtocol() != "dns" {
		t.Errorf("expected dns, got %s", ch.GetProtocol())
	}
}

func TestC2Channel_IsConnected(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{})
	if ch.IsConnected() {
		t.Error("expected not connected initially")
	}
}

func TestC2Channel_ConnectDisconnect(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{})
	err := ch.Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if !ch.IsConnected() {
		t.Error("expected connected after Connect()")
	}
	ch.Disconnect()
	if ch.IsConnected() {
		t.Error("expected not connected after Disconnect()")
	}
}

func TestC2Channel_GetReconnects(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{})
	if ch.GetReconnects() != 0 {
		t.Errorf("expected 0 reconnects, got %d", ch.GetReconnects())
	}
	ch.Reconnect()
	if ch.GetReconnects() != 1 {
		t.Errorf("expected 1 reconnect, got %d", ch.GetReconnects())
	}
}

func TestC2Channel_GetLastIO(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{})
	lastIO := ch.GetLastIO()
	if !lastIO.IsZero() {
		t.Error("expected zero lastIO before connect")
	}
	ch.Connect()
	lastIO = ch.GetLastIO()
	if lastIO.IsZero() {
		t.Error("expected non-zero lastIO after connect")
	}
}

func TestC2Channel_GetAddr(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{Addr: "10.0.0.1", Port: 8080})
	if ch.GetAddr() != "10.0.0.1:8080" {
		t.Errorf("expected 10.0.0.1:8080, got %s", ch.GetAddr())
	}
}

func TestC2Channel_SendNotConnected(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{})
	err := ch.Send([]byte("data"))
	if err == nil {
		t.Error("expected error sending on disconnected channel")
	}
}

func TestC2Channel_SendConnected(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{})
	ch.Connect()
	err := ch.Send([]byte("data"))
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
}

func TestC2Channel_ReceiveNotConnected(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{})
	_, err := ch.Receive()
	if err == nil {
		t.Error("expected error receiving on disconnected channel")
	}
}

func TestC2Channel_ReceiveConnected(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{})
	ch.Connect()
	data, err := ch.Receive()
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}
	if data == nil {
		t.Error("expected non-nil data")
	}
}

func TestC2Channel_RotateKey(t *testing.T) {
	ch := NewC2Channel(ChannelConfig{})
	err := ch.RotateKey()
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}
}
