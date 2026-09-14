package c2implant

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

type SleepController struct {
	mu         sync.Mutex
	baseSleep  time.Duration
	jitter     float64
	totalSleep time.Duration
	sleepCount int64
	sleepCh    chan struct{}
}

func NewSleepController(baseSleep time.Duration, jitter float64) *SleepController {
	if jitter < 0 {
		jitter = 0
	}
	if jitter > 1.0 {
		jitter = 1.0
	}
	if baseSleep < time.Millisecond {
		baseSleep = time.Millisecond
	}

	return &SleepController{
		baseSleep: baseSleep,
		jitter:    jitter,
	}
}

func (sc *SleepController) Sleep(duration time.Duration, jitter float64) time.Duration {
	actualDuration := sc.CalculateSleep(duration, jitter)

	sc.sleepCh = make(chan struct{})
	timer := time.NewTimer(actualDuration)
	select {
	case <-timer.C:
	case <-sc.sleepCh:
		timer.Stop()
	}

	sc.mu.Lock()
	sc.totalSleep += actualDuration
	sc.sleepCount++
	sc.mu.Unlock()

	return actualDuration
}

func (sc *SleepController) Interrupt() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.sleepCh != nil {
		close(sc.sleepCh)
		sc.sleepCh = nil
	}
}

func (sc *SleepController) CalculateSleep(baseSleep time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return baseSleep
	}
	if jitter > 1.0 {
		jitter = 1.0
	}

	return JitterDuration(baseSleep, jitter)
}

func JitterDuration(base time.Duration, jitterPercent float64) time.Duration {
	if jitterPercent <= 0 {
		return base
	}
	if jitterPercent > 1.0 {
		jitterPercent = 1.0
	}

	baseNano := float64(base.Nanoseconds())
	jitterRange := baseNano * jitterPercent

	jitterOffset := (rand.Float64()*2 - 1) * jitterRange
	newNano := baseNano + jitterOffset

	if newNano < 1 {
		newNano = 1
	}

	return time.Duration(math.Round(newNano))
}

func (sc *SleepController) GetStats() (totalSleep time.Duration, count int64) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.totalSleep, sc.sleepCount
}

func (sc *SleepController) ResetStats() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.totalSleep = 0
	sc.sleepCount = 0
}

func (sc *SleepController) SetBaseSleep(d time.Duration) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if d >= time.Millisecond {
		sc.baseSleep = d
	}
}

func (sc *SleepController) SetJitter(j float64) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if j >= 0 && j <= 1.0 {
		sc.jitter = j
	}
}

func (sc *SleepController) GetBaseSleep() time.Duration {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.baseSleep
}

func (sc *SleepController) GetJitter() float64 {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.jitter
}
