package channel_rotation

import (
	"testing"
	"time"
)

func TestNewFailoverLogic(t *testing.T) {
	fl := NewFailoverLogic()
	if fl == nil {
		t.Fatal("NewFailoverLogic returned nil")
	}
	if len(fl.channels) != 0 {
		t.Errorf("expected 0 channels, got %d", len(fl.channels))
	}
	if !fl.autoFailover {
		t.Error("expected autoFailover to be true by default")
	}
	if fl.healthCheck == nil {
		t.Error("expected healthCheck to be initialized")
	}
}

func TestFailoverLogic_AddChannel(t *testing.T) {
	fl := NewFailoverLogic()
	fl.AddChannel(FailoverChannel{ID: "ch1", Type: "https", Addr: "1.2.3.4", Port: 443, Priority: 1})

	if fl.GetChannelCount() != 1 {
		t.Fatalf("expected 1 channel, got %d", fl.GetChannelCount())
	}
	if fl.channels[0].ID != "ch1" {
		t.Errorf("expected ch1, got %s", fl.channels[0].ID)
	}
}

func TestFailoverLogic_RemoveChannel(t *testing.T) {
	fl := NewFailoverLogic()
	fl.AddChannel(FailoverChannel{ID: "ch1", Type: "https"})
	fl.AddChannel(FailoverChannel{ID: "ch2", Type: "dns"})

	fl.RemoveChannel("ch1")

	if fl.GetChannelCount() != 1 {
		t.Fatalf("expected 1 channel, got %d", fl.GetChannelCount())
	}
	if fl.channels[0].ID != "ch2" {
		t.Errorf("expected ch2, got %s", fl.channels[0].ID)
	}
}

func TestFailoverLogic_RemoveChannel_NotFound(t *testing.T) {
	fl := NewFailoverLogic()
	fl.AddChannel(FailoverChannel{ID: "ch1"})

	fl.RemoveChannel("nonexistent")

	if fl.GetChannelCount() != 1 {
		t.Errorf("expected 1 channel, got %d", fl.GetChannelCount())
	}
}

func TestFailoverLogic_GetCurrentChannel_Empty(t *testing.T) {
	fl := NewFailoverLogic()
	if ch := fl.GetCurrentChannel(); ch != nil {
		t.Errorf("expected nil, got %v", ch)
	}
}

func TestFailoverLogic_GetCurrentChannel(t *testing.T) {
	fl := NewFailoverLogic()
	fl.AddChannel(FailoverChannel{ID: "ch1", Type: "https"})
	fl.AddChannel(FailoverChannel{ID: "ch2", Type: "dns"})

	ch := fl.GetCurrentChannel()
	if ch == nil {
		t.Fatal("expected non-nil")
	}
	if ch.ID != "ch1" {
		t.Errorf("expected ch1, got %s", ch.ID)
	}
}

func TestFailoverLogic_Failover_NoChannels(t *testing.T) {
	fl := NewFailoverLogic()
	if ch := fl.Failover(); ch != nil {
		t.Errorf("expected nil, got %v", ch)
	}
}

func TestFailoverLogic_Failover_NoHealthy(t *testing.T) {
	fl := NewFailoverLogic()
	fl.AddChannel(FailoverChannel{ID: "ch1"})

	if ch := fl.Failover(); ch != nil {
		t.Errorf("expected nil when no healthy channels, got %v", ch)
	}
}

func TestFailoverLogic_Failover(t *testing.T) {
	fl := NewFailoverLogic()
	fl.AddChannel(FailoverChannel{ID: "ch1", Type: "https"})
	fl.AddChannel(FailoverChannel{ID: "ch2", Type: "dns"})

	// Mark ch1 healthy
	fl.healthCheck.Update("ch1", true, 0)

	ch := fl.Failover()
	if ch == nil {
		t.Fatal("expected non-nil")
	}
	if ch.ID != "ch1" {
		t.Errorf("expected ch1, got %s", ch.ID)
	}
}

func TestFailoverLogic_Failover_SkipsUnhealthy(t *testing.T) {
	fl := NewFailoverLogic()
	fl.AddChannel(FailoverChannel{ID: "ch1", Type: "https"})
	fl.AddChannel(FailoverChannel{ID: "ch2", Type: "dns"})

	// ch1 unhealthy, ch2 healthy
	fl.healthCheck.Update("ch1", false, 0)
	fl.healthCheck.Update("ch2", true, 0)

	ch := fl.Failover()
	if ch == nil || ch.ID != "ch2" {
		t.Errorf("expected ch2, got %v", ch)
	}
}

func TestFailoverLogic_CheckAndFailover_AutoEnabled(t *testing.T) {
	fl := NewFailoverLogic()
	fl.AddChannel(FailoverChannel{ID: "ch1", Type: "https"})
	fl.healthCheck.Update("ch1", true, 0)

	ch := fl.CheckAndFailover()
	if ch == nil || ch.ID != "ch1" {
		t.Errorf("expected ch1, got %v", ch)
	}
}

func TestFailoverLogic_CheckAndFailover_AutoDisabled(t *testing.T) {
	fl := NewFailoverLogic()
	fl.AddChannel(FailoverChannel{ID: "ch1"})
	fl.SetAutoFailover(false)

	ch := fl.CheckAndFailover()
	if ch == nil || ch.ID != "ch1" {
		t.Errorf("expected ch1 (current), got %v", ch)
	}
}

func TestFailoverLogic_CheckAndFailover_CurrentUnhealthy(t *testing.T) {
	fl := NewFailoverLogic()
	fl.AddChannel(FailoverChannel{ID: "ch1"})
	fl.AddChannel(FailoverChannel{ID: "ch2"})

	// ch1 (current) unhealthy, ch2 healthy
	fl.healthCheck.Update("ch1", false, 0)
	fl.healthCheck.Update("ch2", true, 0)

	ch := fl.CheckAndFailover()
	if ch == nil || ch.ID != "ch2" {
		t.Errorf("expected failover to ch2, got %v", ch)
	}
}

func TestFailoverLogic_StopAutoFailover(t *testing.T) {
	fl := NewFailoverLogic()
	fl.StartAutoFailover(50 * time.Millisecond)

	// Let a tick happen
	time.Sleep(100 * time.Millisecond)

	fl.StopAutoFailover()
	// Should not panic
}

func TestFailoverLogic_GetHealthCheck(t *testing.T) {
	fl := NewFailoverLogic()
	hc := fl.GetHealthCheck()
	if hc == nil {
		t.Error("expected non-nil health check")
	}
}

func TestFailoverLogic_SetAutoFailover(t *testing.T) {
	fl := NewFailoverLogic()

	fl.SetAutoFailover(false)
	if fl.autoFailover {
		t.Error("expected autoFailover to be false")
	}

	fl.SetAutoFailover(true)
	if !fl.autoFailover {
		t.Error("expected autoFailover to be true")
	}
}

func TestFailoverLogic_GetChannelCount(t *testing.T) {
	fl := NewFailoverLogic()
	if fl.GetChannelCount() != 0 {
		t.Errorf("expected 0, got %d", fl.GetChannelCount())
	}

	fl.AddChannel(FailoverChannel{ID: "ch1"})
	if fl.GetChannelCount() != 1 {
		t.Errorf("expected 1, got %d", fl.GetChannelCount())
	}
}

func TestFailoverLogic_GetHealthyChannelCount(t *testing.T) {
	fl := NewFailoverLogic()
	fl.AddChannel(FailoverChannel{ID: "ch1"})
	fl.AddChannel(FailoverChannel{ID: "ch2"})
	fl.AddChannel(FailoverChannel{ID: "ch3"})

	fl.healthCheck.Update("ch1", true, 0)
	fl.healthCheck.Update("ch2", false, 0)
	fl.healthCheck.Update("ch3", true, 0)

	if fl.GetHealthyChannelCount() != 2 {
		t.Errorf("expected 2 healthy channels, got %d", fl.GetHealthyChannelCount())
	}
}

func TestFailoverLogic_GetHealthyChannelCount_None(t *testing.T) {
	fl := NewFailoverLogic()
	fl.AddChannel(FailoverChannel{ID: "ch1"})
	// ch1 not in healthCheck → IsHealthy returns false

	if fl.GetHealthyChannelCount() != 0 {
		t.Errorf("expected 0, got %d", fl.GetHealthyChannelCount())
	}
}
