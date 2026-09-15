package brain

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

type TimingControl struct {
	mu            sync.RWMutex
	baseSleep     time.Duration
	jitter        float64
	lastActivity  time.Time
	suspicionLevel float64
}

func NewTimingControl(baseSleep time.Duration, jitter float64) *TimingControl {
	return &TimingControl{
		baseSleep:     baseSleep,
		jitter:        jitter,
		lastActivity:  time.Now(),
		suspicionLevel: 0,
	}
}

func (t *TimingControl) CalculateSleep() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()

	baseMs := float64(t.baseSleep.Milliseconds())
	jitterMs := baseMs * t.jitter

	suspicionMultiplier := 1.0 + (t.suspicionLevel * 2.0)
	adjustedJitter := jitterMs * suspicionMultiplier

	randomJitter := (rand.Float64()*2 - 1) * adjustedJitter
	sleepMs := baseMs + randomJitter

	if sleepMs < 1000 {
		sleepMs = 1000
	}

	return time.Duration(sleepMs) * time.Millisecond
}

func (t *TimingControl) UpdateSuspicion(level float64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.suspicionLevel = math.Max(0, math.Min(1, level))
}

func (t *TimingControl) IncreaseSuspicion(amount float64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.suspicionLevel = math.Min(1, t.suspicionLevel+amount)
}

func (t *TimingControl) DecreaseSuspicion(amount float64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.suspicionLevel = math.Max(0, t.suspicionLevel-amount)
}

func (t *TimingControl) GetSuspicionLevel() float64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.suspicionLevel
}

func (t *TimingControl) UpdateActivity() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastActivity = time.Now()
}

func (t *TimingControl) TimeSinceActivity() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return time.Since(t.lastActivity)
}

func (t *TimingControl) ShouldSleep() bool {
	suspicion := t.GetSuspicionLevel()
	return suspicion > 0.7
}
