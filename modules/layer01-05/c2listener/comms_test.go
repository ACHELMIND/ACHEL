package c2listener

import (
	"testing"
)

func TestNewC2Comms(t *testing.T) {
	c := NewC2Comms(CommsConfig{})
	if c == nil {
		t.Fatal("expected non-nil C2Comms")
	}
	if c.channels == nil {
		t.Error("expected non-nil channels map")
	}
}

func TestC2Comms_AddRemoveChannel(t *testing.T) {
	c := NewC2Comms(CommsConfig{})
	ch := NewC2Channel(ChannelConfig{
		Protocol: "tcp",
		Addr:     "127.0.0.1",
		Port:     9090,
	})
	c.AddChannel(ch)
	if c.GetChannelCount() != 1 {
		t.Errorf("expected 1 channel, got %d", c.GetChannelCount())
	}
	c.RemoveChannel(ch.GetID())
	if c.GetChannelCount() != 0 {
		t.Errorf("expected 0 channels after remove, got %d", c.GetChannelCount())
	}
}

func TestC2Comms_RemoveNonExistent(t *testing.T) {
	c := NewC2Comms(CommsConfig{})
	c.RemoveChannel("nonexistent")
}

func TestC2Comms_GetChannelCount(t *testing.T) {
	c := NewC2Comms(CommsConfig{})
	ch1 := NewC2Channel(ChannelConfig{Protocol: "tcp", Addr: "127.0.0.1", Port: 9091})
	ch2 := NewC2Channel(ChannelConfig{Protocol: "udp", Addr: "127.0.0.1", Port: 9092})
	c.AddChannel(ch1)
	c.AddChannel(ch2)
	if c.GetChannelCount() != 2 {
		t.Errorf("expected 2 channels, got %d", c.GetChannelCount())
	}
}

func TestC2Comms_GetCurrentChannel(t *testing.T) {
	c := NewC2Comms(CommsConfig{})
	if c.GetCurrentChannel() != nil {
		t.Error("expected nil current channel")
	}
	ch := NewC2Channel(ChannelConfig{Protocol: "tcp", Addr: "127.0.0.1", Port: 9090})
	c.AddChannel(ch)
	if c.GetCurrentChannel() == nil {
		t.Error("expected non-nil current channel after add")
	}
}

func TestC2Comms_GetChannels(t *testing.T) {
	c := NewC2Comms(CommsConfig{})
	ch1 := NewC2Channel(ChannelConfig{Protocol: "tcp", Addr: "127.0.0.1", Port: 9091})
	ch2 := NewC2Channel(ChannelConfig{Protocol: "udp", Addr: "127.0.0.1", Port: 9092})
	c.AddChannel(ch1)
	c.AddChannel(ch2)
	channels := c.GetChannels()
	if len(channels) != 2 {
		t.Errorf("expected 2 channels, got %d", len(channels))
	}
}

func TestC2Comms_RotateChannel(t *testing.T) {
	c := NewC2Comms(CommsConfig{})
	ch1 := NewC2Channel(ChannelConfig{Protocol: "tcp", Addr: "127.0.0.1", Port: 9091})
	ch2 := NewC2Channel(ChannelConfig{Protocol: "udp", Addr: "127.0.0.1", Port: 9092})
	c.AddChannel(ch1)
	c.AddChannel(ch2)
	rotated := c.RotateChannel()
	if rotated == nil {
		t.Error("expected non-nil rotated channel")
	}
}

func TestC2Comms_RotateChannelEmpty(t *testing.T) {
	c := NewC2Comms(CommsConfig{})
	rotated := c.RotateChannel()
	if rotated != nil {
		t.Error("expected nil when no channels")
	}
}

func TestC2Comms_Encryption(t *testing.T) {
	c := NewC2Comms(CommsConfig{Encryption: true})
	if !c.IsEncrypted() {
		t.Error("expected encrypted")
	}
	c.SetEncryption(false)
	if c.IsEncrypted() {
		t.Error("expected not encrypted after disable")
	}
}

func TestC2Comms_Compression(t *testing.T) {
	c := NewC2Comms(CommsConfig{Compression: true})
	if !c.IsCompressed() {
		t.Error("expected compressed")
	}
	c.SetCompression(false)
	if c.IsCompressed() {
		t.Error("expected not compressed after disable")
	}
}

func TestC2Comms_SendMessageNoChannel(t *testing.T) {
	c := NewC2Comms(CommsConfig{})
	err := c.SendMessage(&Message{Payload: []byte("test")})
	if err == nil {
		t.Error("expected error sending with no channel")
	}
}

func TestC2Comms_ReceiveMessageNoChannel(t *testing.T) {
	c := NewC2Comms(CommsConfig{})
	_, err := c.ReceiveMessage()
	if err == nil {
		t.Error("expected error receiving with no channel")
	}
}

func TestC2Comms_GetChannel(t *testing.T) {
	c := NewC2Comms(CommsConfig{})
	ch := NewC2Channel(ChannelConfig{Protocol: "tcp", Addr: "127.0.0.1", Port: 9090})
	c.AddChannel(ch)
	got := c.GetChannel(ch.GetID())
	if got == nil {
		t.Error("expected non-nil channel")
	}
	if got.GetID() != ch.GetID() {
		t.Errorf("channel ID mismatch: expected %s, got %s", ch.GetID(), got.GetID())
	}
}

func TestC2Comms_GetChannelNonexistent(t *testing.T) {
	c := NewC2Comms(CommsConfig{})
	if c.GetChannel("nonexistent") != nil {
		t.Error("expected nil for nonexistent channel")
	}
}
