package channel_rotation

import (
	"sync"
	"testing"
	"time"
)

func TestNewChannelHealth(t *testing.T) {
	ch := NewChannelHealth()
	if ch == nil {
		t.Fatal("NewChannelHealth returned nil")
	}
	if len(ch.channels) != 0 {
		t.Errorf("expected 0 channels, got %d", len(ch.channels))
	}
}

func TestChannelHealth_Update_New(t *testing.T) {
	ch := NewChannelHealth()
	ch.Update("ch1", true, 10*time.Millisecond)

	if !ch.IsHealthy("ch1") {
		t.Error("expected ch1 to be healthy")
	}
	status := ch.GetStatus("ch1")
	if status == nil {
		t.Fatal("expected status for ch1")
	}
	if status.ErrorCount != 0 {
		t.Errorf("expected 0 errors, got %d", status.ErrorCount)
	}
	if status.SuccessRate != 1.0 {
		t.Errorf("expected 1.0 success rate, got %f", status.SuccessRate)
	}
}

func TestChannelHealth_Update_Existing(t *testing.T) {
	ch := NewChannelHealth()

	// First healthy check
	ch.Update("ch1", true, 10*time.Millisecond)
	s1 := ch.GetStatus("ch1")
	rate1 := s1.SuccessRate

	// Unhealthy check
	ch.Update("ch1", false, 50*time.Millisecond)
	s2 := ch.GetStatus("ch1")
	if s2.ErrorCount != 1 {
		t.Errorf("expected 1 error, got %d", s2.ErrorCount)
	}
	if s2.SuccessRate >= rate1 {
		t.Error("expected success rate to decrease after failure")
	}
	if s2.Latency != 50*time.Millisecond {
		t.Errorf("expected 50ms latency, got %v", s2.Latency)
	}

	// Another healthy check
	ch.Update("ch1", true, 20*time.Millisecond)
	s3 := ch.GetStatus("ch1")
	if s3.ErrorCount != 0 {
		t.Errorf("expected error count reset to 0, got %d", s3.ErrorCount)
	}
}

func TestChannelHealth_IsHealthy(t *testing.T) {
	ch := NewChannelHealth()

	if ch.IsHealthy("nonexistent") {
		t.Error("expected nonexistent to not be healthy")
	}

	ch.Update("ch1", true, 0)
	if !ch.IsHealthy("ch1") {
		t.Error("expected ch1 to be healthy")
	}

	ch.Update("ch1", false, 0)
	if ch.IsHealthy("ch1") {
		t.Error("expected ch1 to be unhealthy")
	}
}

func TestChannelHealth_GetStatus(t *testing.T) {
	ch := NewChannelHealth()

	if ch.GetStatus("nonexistent") != nil {
		t.Error("expected nil for nonexistent")
	}

	ch.Update("ch1", true, 10*time.Millisecond)
	s := ch.GetStatus("ch1")
	if s == nil {
		t.Fatal("expected non-nil status")
	}
	if s.ChannelID != "ch1" {
		t.Errorf("expected ch1, got %s", s.ChannelID)
	}
}

func TestChannelHealth_GetAllStatuses(t *testing.T) {
	ch := NewChannelHealth()
	ch.Update("ch1", true, 10*time.Millisecond)
	ch.Update("ch2", false, 50*time.Millisecond)

	statuses := ch.GetAllStatuses()
	if len(statuses) != 2 {
		t.Errorf("expected 2 statuses, got %d", len(statuses))
	}
	if _, ok := statuses["ch1"]; !ok {
		t.Error("expected ch1 in statuses")
	}
	if _, ok := statuses["ch2"]; !ok {
		t.Error("expected ch2 in statuses")
	}
}

func TestChannelHealth_GetBestChannel(t *testing.T) {
	ch := NewChannelHealth()

	// No channels
	if best := ch.GetBestChannel(); best != "" {
		t.Errorf("expected empty string, got %s", best)
	}

	// Two channels: ch1 has low latency + high success, ch2 has high latency
	ch.Update("ch1", true, 5*time.Millisecond)
	ch.Update("ch2", true, 500*time.Millisecond)

	best := ch.GetBestChannel()
	if best != "ch1" {
		t.Errorf("expected ch1 as best, got %s", best)
	}
}

func TestChannelHealth_GetBestChannel_OnlyHealthy(t *testing.T) {
	ch := NewChannelHealth()
	ch.Update("ch1", false, 5*time.Millisecond) // unhealthy
	ch.Update("ch2", true, 10*time.Millisecond)  // healthy

	best := ch.GetBestChannel()
	if best != "ch2" {
		t.Errorf("expected ch2 as best, got %s", best)
	}
}

func TestChannelHealth_MarkUnhealthy(t *testing.T) {
	ch := NewChannelHealth()
	ch.Update("ch1", true, 0)

	ch.MarkUnhealthy("ch1")
	if ch.IsHealthy("ch1") {
		t.Error("expected ch1 to be unhealthy")
	}
	s := ch.GetStatus("ch1")
	if s.ErrorCount != 1 {
		t.Errorf("expected 1 error, got %d", s.ErrorCount)
	}

	// Mark again
	ch.MarkUnhealthy("ch1")
	s = ch.GetStatus("ch1")
	if s.ErrorCount != 2 {
		t.Errorf("expected 2 errors, got %d", s.ErrorCount)
	}
}

func TestChannelHealth_MarkHealthy(t *testing.T) {
	ch := NewChannelHealth()
	ch.Update("ch1", false, 0)
	ch.MarkUnhealthy("ch1")

	ch.MarkHealthy("ch1")
	if !ch.IsHealthy("ch1") {
		t.Error("expected ch1 to be healthy")
	}
	s := ch.GetStatus("ch1")
	if s.ErrorCount != 0 {
		t.Errorf("expected 0 errors after MarkHealthy, got %d", s.ErrorCount)
	}
}

func TestChannelHealth_MarkUnhealthy_Nonexistent(t *testing.T) {
	ch := NewChannelHealth()
	// Should not panic
	ch.MarkUnhealthy("nonexistent")
	ch.MarkHealthy("nonexistent")
}

func TestChannelHealth_ConcurrentAccess(t *testing.T) {
	ch := NewChannelHealth()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			id := "ch" + string(rune('0'+n%10))
			ch.Update(id, n%2 == 0, time.Duration(n)*time.Millisecond)
		}(i)
		go func(n int) {
			defer wg.Done()
			id := "ch" + string(rune('0'+n%10))
			ch.IsHealthy(id)
			ch.GetStatus(id)
		}(i)
	}
	wg.Wait()
}

func TestSuccessRateCalculation(t *testing.T) {
	// All healthy: should be 1.0
	ch1 := NewChannelHealth()
	ch1.Update("a", true, 0)
	ch1.Update("b", true, 0)
	ch1.Update("c", true, 0)
	s1 := ch1.GetStatus("a")
	if s1.SuccessRate != 1.0 {
		t.Errorf("expected 1.0 after all healthy, got %f", s1.SuccessRate)
	}

	// Test alternating healthy/unhealthy (ErrorCount resets on healthy)
	ch2 := NewChannelHealth()
	ch2.Update("c", true, 0)  // new: SuccessRate=1.0, ErrorCount=0
	ch2.Update("c", false, 0) // unhealthy: ErrorCount=1, totalChecks=2, SuccessRate=0.5
	ch2.Update("c", true, 0)  // healthy: ErrorCount=0, totalChecks=1, SuccessRate=1.0
	s2 := ch2.GetStatus("c")
	if s2.SuccessRate != 1.0 {
		t.Errorf("expected 1.0 (healthy resets ErrorCount), got %f", s2.SuccessRate)
	}

	// Test multiple consecutive failures
	ch3 := NewChannelHealth()
	ch3.Update("d", true, 0)  // new: SuccessRate=1.0, ErrorCount=0
	ch3.Update("d", false, 0) // unhealthy: ErrorCount=1, totalChecks=2, SuccessRate=0.5
	ch3.Update("d", false, 0) // unhealthy: ErrorCount=2, totalChecks=3, SuccessRate=0.5*2/3=0.333
	s3 := ch3.GetStatus("d")
	if s3.SuccessRate < 0.33 || s3.SuccessRate > 0.34 {
		t.Errorf("expected ~0.333 after 2 consecutive failures, got %f", s3.SuccessRate)
	}
}
