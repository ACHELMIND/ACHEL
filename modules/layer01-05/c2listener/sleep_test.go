package c2listener

import (
	"testing"
	"time"
)

func TestNewSleepMasker(t *testing.T) {
	sm := NewSleepMasker(SleepConfig{
		Jitter:     0.2,
		MinSleep:   100 * time.Millisecond,
		MaxSleep:   500 * time.Millisecond,
		SleepMethod: "standard",
		Encrypted:  true,
	})
	if sm == nil {
		t.Fatal("expected non-nil SleepMasker")
	}
	if sm.jitter != 0.2 {
		t.Errorf("expected jitter 0.2, got %f", sm.jitter)
	}
}

func TestNewSleepMasker_Defaults(t *testing.T) {
	sm := NewSleepMasker(SleepConfig{})
	if sm.jitter != 0.25 {
		t.Errorf("expected default jitter 0.25, got %f", sm.jitter)
	}
	if sm.minSleep != 5*time.Second {
		t.Errorf("expected default minSleep 5s, got %v", sm.minSleep)
	}
	if sm.maxSleep != 60*time.Second {
		t.Errorf("expected default maxSleep 60s, got %v", sm.maxSleep)
	}
}

func TestSleepMasker_Sleep(t *testing.T) {
	sm := NewSleepMasker(SleepConfig{
		MinSleep: 1 * time.Millisecond,
		MaxSleep: 5 * time.Millisecond,
	})
	start := time.Now()
	dur := sm.Sleep()
	elapsed := time.Since(start)
	if elapsed < 1*time.Millisecond {
		t.Errorf("sleep too short: %v", elapsed)
	}
	if dur < 1*time.Millisecond {
		t.Errorf("returned duration too short: %v", dur)
	}
}

func TestSleepMasker_SleepWithJitter(t *testing.T) {
	sm := NewSleepMasker(SleepConfig{
		Jitter:   0.5,
		MinSleep: 1 * time.Millisecond,
		MaxSleep: 10 * time.Millisecond,
	})
	dur := sm.SleepWithJitter()
	if dur < 1*time.Millisecond {
		t.Errorf("jitter duration too short: %v", dur)
	}
}

func TestSleepMasker_CalculateSleepDuration(t *testing.T) {
	sm := NewSleepMasker(SleepConfig{
		MinSleep: 100 * time.Millisecond,
		MaxSleep: 200 * time.Millisecond,
	})
	d := sm.calculateSleepDuration()
	if d < 100*time.Millisecond || d > 200*time.Millisecond {
		t.Errorf("duration out of range: %v", d)
	}
}

func TestSleepMasker_GetHistory(t *testing.T) {
	sm := NewSleepMasker(SleepConfig{
		MinSleep: 1 * time.Millisecond,
		MaxSleep: 2 * time.Millisecond,
	})
	sm.Sleep()
	sm.Sleep()
	history := sm.GetHistory()
	if len(history) != 2 {
		t.Errorf("expected 2 history entries, got %d", len(history))
	}
}

func TestSleepMasker_IsMasked(t *testing.T) {
	sm := NewSleepMasker(SleepConfig{})
	if sm.IsMasked() {
		t.Error("expected not masked initially")
	}
	sm.Mask()
	if !sm.IsMasked() {
		t.Error("expected masked after Mask()")
	}
	sm.Unmask()
	if sm.IsMasked() {
		t.Error("expected not masked after Unmask()")
	}
}

func TestSleepMasker_SetJitter(t *testing.T) {
	sm := NewSleepMasker(SleepConfig{})
	sm.SetJitter(0.5)
	if sm.jitter != 0.5 {
		t.Errorf("expected jitter 0.5, got %f", sm.jitter)
	}
}

func TestSleepMasker_SetSleepMethod(t *testing.T) {
	sm := NewSleepMasker(SleepConfig{})
	sm.SetSleepMethod("api")
	if sm.sleepMethod != "api" {
		t.Errorf("expected sleepMethod api, got %s", sm.sleepMethod)
	}
}

func TestSleepMasker_GetAvgSleepDuration(t *testing.T) {
	sm := NewSleepMasker(SleepConfig{
		MinSleep: 1 * time.Millisecond,
		MaxSleep: 2 * time.Millisecond,
	})
	avg := sm.GetAvgSleepDuration()
	if avg != 0 {
		t.Errorf("expected 0 avg with no history, got %v", avg)
	}
	sm.Sleep()
	sm.Sleep()
	avg = sm.GetAvgSleepDuration()
	if avg <= 0 {
		t.Errorf("expected positive avg, got %v", avg)
	}
}
