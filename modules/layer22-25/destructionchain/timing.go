package destructionchain

import (
	"fmt"
	"math/rand"
	"time"
)

func NewTimingCoordinator(config *TimingConfig) *TimingCoordinator {
	if config == nil {
		config = NewDefaultTimingConfig()
	}
	return &TimingCoordinator{
		config:   config,
		schedule: make(map[string]*ScheduledStep),
		chain:    make(map[string]*ChainProgress),
	}
}

func (tc *TimingCoordinator) ScheduleStep(step *ChainStep, delay time.Duration) error {
	if step == nil {
		return fmt.Errorf("step is nil")
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	jitter := time.Duration(float64(delay) * tc.config.Jitter * (rand.Float64()*2 - 1))
	actualDelay := delay + jitter

	if actualDelay < tc.config.MinDelay {
		actualDelay = tc.config.MinDelay
	}
	if actualDelay > tc.config.MaxDelay {
		actualDelay = tc.config.MaxDelay
	}

	tc.schedule[step.ID] = &ScheduledStep{
		Step:       step,
		ScheduleAt: time.Now().Add(actualDelay),
		Delay:      actualDelay,
		Cancelled:  false,
	}

	return nil
}

func (tc *TimingCoordinator) SyncSteps(steps []ChainStep) error {
	if len(steps) == 0 {
		return nil
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	baseDelay := tc.config.MinDelay
	for i := range steps {
		delay := baseDelay * time.Duration(i+1)
		jitter := time.Duration(float64(delay) * tc.config.Jitter * (rand.Float64()*2 - 1))
		actualDelay := delay + jitter

		if actualDelay < tc.config.MinDelay {
			actualDelay = tc.config.MinDelay
		}

		tc.schedule[steps[i].ID] = &ScheduledStep{
			Step:       &steps[i],
			ScheduleAt: time.Now().Add(actualDelay),
			Delay:      actualDelay,
			Cancelled:  false,
		}
	}

	return nil
}

func (tc *TimingCoordinator) GetChainProgress(chainID string) *ChainProgress {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	progress, ok := tc.chain[chainID]
	if !ok {
		return &ChainProgress{
			ChainID:    chainID,
			Status:     ChainStatusPending,
			TotalSteps: 0,
			Percentage: 0,
		}
	}
	return progress
}

func (tc *TimingCoordinator) UpdateProgress(chainID string, progress *ChainProgress) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.chain[chainID] = progress
}

func (tc *TimingCoordinator) CalculateETA(totalSteps, completedSteps int, avgStepTime time.Duration) time.Duration {
	if completedSteps == 0 || totalSteps == 0 {
		return 0
	}
	remaining := totalSteps - completedSteps
	return avgStepTime * time.Duration(remaining)
}

func (tc *TimingCoordinator) ShouldSync() bool {
	return tc.config.SyncEnabled
}

func (tc *TimingCoordinator) GetDelayForStep(stepIndex, totalSteps int) time.Duration {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	base := tc.config.MinDelay
	multiplier := time.Duration(stepIndex+1)
	delay := base * multiplier

	jitter := time.Duration(float64(delay) * tc.config.Jitter * (rand.Float64()*2 - 1))
	delay += jitter

	if delay < tc.config.MinDelay {
		delay = tc.config.MinDelay
	}
	if delay > tc.config.MaxDelay {
		delay = tc.config.MaxDelay
	}

	return delay
}
