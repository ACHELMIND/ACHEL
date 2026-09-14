package brain

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

type TimingController struct {
	config *BrainConfig
	state  *TimingState
	mu     sync.RWMutex
}

func NewTimingController(config *BrainConfig) *TimingController {
	return &TimingController{
		config: config,
		state: &TimingState{
			CurrentDelay: config.MinDelay,
			SuccessRate:  0.5,
		},
	}
}

func (tc *TimingController) CalculateDelay(riskLevel float64) time.Duration {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	baseDelay := tc.config.MinDelay
	maxDelay := tc.config.MaxDelay

	riskFactor := 1.0 + riskLevel*2.0
	delay := time.Duration(float64(baseDelay) * riskFactor)

	if delay > maxDelay {
		delay = maxDelay
	}
	if delay < tc.config.MinDelay {
		delay = tc.config.MinDelay
	}

	jitter := 0.8 + rand.Float64()*0.4
	delay = time.Duration(float64(delay) * jitter)

	return delay
}

func (tc *TimingController) AdaptTiming(successRate float64) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.state.SuccessRate = successRate

	base := float64(tc.config.MinDelay)
	max := float64(tc.config.MaxDelay)

	if successRate > 0.8 {
		newDelay := base * 0.8
		tc.state.CurrentDelay = time.Duration(math.Max(newDelay, float64(tc.config.MinDelay)))
	} else if successRate < 0.3 {
		newDelay := float64(tc.state.CurrentDelay) * 1.5
		tc.state.CurrentDelay = time.Duration(math.Min(newDelay, float64(tc.config.MaxDelay)))
	} else {
		newDelay := base + (max-base)*(1-successRate)
		tc.state.CurrentDelay = time.Duration(newDelay)
	}
}

func (tc *TimingController) ShouldSleep() bool {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	if !tc.config.AdaptiveTiming {
		return false
	}

	if tc.state.SuccessRate < 0.2 {
		return true
	}

	return false
}

func (tc *TimingController) GetCurrentDelay() time.Duration {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.state.CurrentDelay
}

func (tc *TimingController) GetState() *TimingState {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	return &TimingState{
		CurrentDelay: tc.state.CurrentDelay,
		SuccessRate:  tc.state.SuccessRate,
		LastSleep:    tc.state.LastSleep,
		SleepCount:   tc.state.SleepCount,
	}
}

func (tc *TimingController) RecordSleep() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.state.LastSleep = time.Now()
	tc.state.SleepCount++
}
