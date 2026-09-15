package brain

import (
	"sync"
	"time"
)

type BehaviorLearning struct {
	mu         sync.RWMutex
	patterns   map[string]*Pattern
	history    []BehaviorEvent
}

type Pattern struct {
	ID          string
	Name        string
	Frequency   int
	LastSeen    time.Time
	SuccessRate float64
}

type BehaviorEvent struct {
	Action    string
	Success   bool
	Duration  time.Duration
	Timestamp time.Time
}

func NewBehaviorLearning() *BehaviorLearning {
	return &BehaviorLearning{
		patterns: make(map[string]*Pattern),
		history:  make([]BehaviorEvent, 0),
	}
}

func (b *BehaviorLearning) RecordEvent(event BehaviorEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.history = append(b.history, event)

	if pattern, exists := b.patterns[event.Action]; exists {
		pattern.Frequency++
		pattern.LastSeen = time.Now()
		totalEvents := float64(pattern.Frequency)
		successes := pattern.SuccessRate * (totalEvents - 1)
		if event.Success {
			successes++
		}
		pattern.SuccessRate = successes / totalEvents
	} else {
		b.patterns[event.Action] = &Pattern{
			ID:          event.Action,
			Name:        event.Action,
			Frequency:   1,
			LastSeen:    time.Now(),
			SuccessRate: 1.0,
		}
	}
}

func (b *BehaviorLearning) PredictSuccess(action string) float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if pattern, exists := b.patterns[action]; exists {
		return pattern.SuccessRate
	}
	return 0.5
}

func (b *BehaviorLearning) GetMostEffective() string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bestAction := ""
	bestScore := 0.0

	for action, pattern := range b.patterns {
		score := float64(pattern.Frequency) * pattern.SuccessRate
		if score > bestScore {
			bestScore = score
			bestAction = action
		}
	}

	return bestAction
}

func (b *BehaviorLearning) GetRecentHistory(count int) []BehaviorEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if count > len(b.history) {
		count = len(b.history)
	}

	return b.history[len(b.history)-count:]
}
