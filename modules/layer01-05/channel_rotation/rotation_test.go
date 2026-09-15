package channel_rotation

import (
	"sync"
	"testing"
	"time"
)

func TestNewChannelRotation(t *testing.T) {
	cr := NewChannelRotation()
	if cr == nil {
		t.Fatal("NewChannelRotation returned nil")
	}
	if len(cr.channels) != 0 {
		t.Errorf("expected 0 channels, got %d", len(cr.channels))
	}
	if len(cr.healthChecks) != 0 {
		t.Errorf("expected 0 health checks, got %d", len(cr.healthChecks))
	}
}

func TestAddChannel(t *testing.T) {
	cr := NewChannelRotation()
	ch := Channel{ID: "ch1", Type: "https", Addr: "1.2.3.4", Port: 443}
	cr.AddChannel(ch)

	if len(cr.channels) != 1 {
		t.Fatalf("expected 1 channel, got %d", len(cr.channels))
	}
	if cr.channels[0].ID != "ch1" {
		t.Errorf("expected channel ID ch1, got %s", cr.channels[0].ID)
	}
	if !cr.healthChecks["ch1"] {
		t.Error("expected ch1 to be healthy by default")
	}
}

func TestRemoveChannel(t *testing.T) {
	cr := NewChannelRotation()
	cr.AddChannel(Channel{ID: "ch1", Type: "https"})
	cr.AddChannel(Channel{ID: "ch2", Type: "dns"})

	cr.RemoveChannel("ch1")

	if len(cr.channels) != 1 {
		t.Fatalf("expected 1 channel, got %d", len(cr.channels))
	}
	if cr.channels[0].ID != "ch2" {
		t.Errorf("expected remaining channel ch2, got %s", cr.channels[0].ID)
	}
	if _, exists := cr.healthChecks["ch1"]; exists {
		t.Error("expected ch1 health check to be deleted")
	}
}

func TestRemoveChannel_NotFound(t *testing.T) {
	cr := NewChannelRotation()
	cr.AddChannel(Channel{ID: "ch1"})

	cr.RemoveChannel("nonexistent")

	if len(cr.channels) != 1 {
		t.Errorf("expected 1 channel, got %d", len(cr.channels))
	}
}

func TestGetCurrentChannel_Empty(t *testing.T) {
	cr := NewChannelRotation()
	if ch := cr.GetCurrentChannel(); ch != nil {
		t.Errorf("expected nil, got %v", ch)
	}
}

func TestGetCurrentChannel(t *testing.T) {
	cr := NewChannelRotation()
	cr.AddChannel(Channel{ID: "ch1", Type: "https"})
	cr.AddChannel(Channel{ID: "ch2", Type: "dns"})

	ch := cr.GetCurrentChannel()
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}
	if ch.ID != "ch1" {
		t.Errorf("expected ch1, got %s", ch.ID)
	}
}

func TestRotate_Empty(t *testing.T) {
	cr := NewChannelRotation()
	if ch := cr.Rotate(); ch != nil {
		t.Errorf("expected nil, got %v", ch)
	}
}

func TestRotate(t *testing.T) {
	cr := NewChannelRotation()
	cr.AddChannel(Channel{ID: "ch1", Type: "https"})
	cr.AddChannel(Channel{ID: "ch2", Type: "dns"})
	cr.AddChannel(Channel{ID: "ch3", Type: "websocket"})

	ch1 := cr.Rotate()
	if ch1.ID != "ch2" {
		t.Errorf("expected ch2, got %s", ch1.ID)
	}

	ch2 := cr.Rotate()
	if ch2.ID != "ch3" {
		t.Errorf("expected ch3, got %s", ch2.ID)
	}

	ch3 := cr.Rotate()
	if ch3.ID != "ch1" {
		t.Errorf("expected ch1 (wrap-around), got %s", ch3.ID)
	}
}

func TestFailover_NoChannels(t *testing.T) {
	cr := NewChannelRotation()
	if ch := cr.Failover(); ch != nil {
		t.Errorf("expected nil, got %v", ch)
	}
}

func TestFailover_NoHealthy(t *testing.T) {
	cr := NewChannelRotation()
	cr.AddChannel(Channel{ID: "ch1", Type: "https"})
	cr.SetHealth("ch1", false)

	if ch := cr.Failover(); ch != nil {
		t.Errorf("expected nil when no healthy channels, got %v", ch)
	}
}

func TestFailover(t *testing.T) {
	cr := NewChannelRotation()
	cr.AddChannel(Channel{ID: "ch1", Type: "https"})
	cr.AddChannel(Channel{ID: "ch2", Type: "dns"})
	cr.SetHealth("ch1", false)

	ch := cr.Failover()
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}
	if ch.ID != "ch2" {
		t.Errorf("expected ch2 (first healthy), got %s", ch.ID)
	}
}

func TestCheckHealth(t *testing.T) {
	cr := NewChannelRotation()
	cr.AddChannel(Channel{ID: "ch1"})

	if !cr.CheckHealth("ch1") {
		t.Error("expected ch1 to be healthy by default")
	}
	if cr.CheckHealth("nonexistent") {
		t.Error("expected nonexistent to not be healthy")
	}
}

func TestSetHealth(t *testing.T) {
	cr := NewChannelRotation()
	cr.AddChannel(Channel{ID: "ch1"})

	cr.SetHealth("ch1", false)
	if cr.CheckHealth("ch1") {
		t.Error("expected ch1 to be unhealthy")
	}

	cr.SetHealth("ch1", true)
	if !cr.CheckHealth("ch1") {
		t.Error("expected ch1 to be healthy again")
	}
}

func TestGetHealthyChannels(t *testing.T) {
	cr := NewChannelRotation()
	cr.AddChannel(Channel{ID: "ch1", Type: "https"})
	cr.AddChannel(Channel{ID: "ch2", Type: "dns"})
	cr.AddChannel(Channel{ID: "ch3", Type: "ws"})
	cr.SetHealth("ch2", false)

	healthy := cr.GetHealthyChannels()
	if len(healthy) != 2 {
		t.Fatalf("expected 2 healthy channels, got %d", len(healthy))
	}
	for _, ch := range healthy {
		if ch.ID == "ch2" {
			t.Error("ch2 should not be in healthy list")
		}
	}
}

func TestGetChannelCount(t *testing.T) {
	cr := NewChannelRotation()
	if cr.GetChannelCount() != 0 {
		t.Errorf("expected 0, got %d", cr.GetChannelCount())
	}

	cr.AddChannel(Channel{ID: "ch1"})
	cr.AddChannel(Channel{ID: "ch2"})
	if cr.GetChannelCount() != 2 {
		t.Errorf("expected 2, got %d", cr.GetChannelCount())
	}

	cr.RemoveChannel("ch1")
	if cr.GetChannelCount() != 1 {
		t.Errorf("expected 1, got %d", cr.GetChannelCount())
	}
}

func TestConcurrentAccess(t *testing.T) {
	cr := NewChannelRotation()
	var wg sync.WaitGroup

	// Concurrent adds
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			cr.AddChannel(Channel{ID: "ch" + string(rune('0'+n%10)), Type: "https"})
		}(i)
	}
	wg.Wait()

	// Concurrent reads and rotations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cr.GetCurrentChannel()
			cr.GetChannelCount()
			cr.GetHealthyChannels()
		}()
	}
	wg.Wait()
}

func TestStartHealthCheck(t *testing.T) {
	cr := NewChannelRotation()
	cr.AddChannel(Channel{ID: "ch1"})

	done := make(chan struct{})
	go func() {
		cr.StartHealthCheck(50 * time.Millisecond)
		close(done)
	}()

	// Let a few ticks happen
	time.Sleep(200 * time.Millisecond)
	_ = done

	// Cleanup - the goroutine will leak but that's expected in tests
	// The failoverTimer keeps the goroutine alive
}
