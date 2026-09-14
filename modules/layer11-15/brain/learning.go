package brain

import (
	"sync"
	"time"
)

type BehaviorLearner struct {
	config   *BrainConfig
	patterns map[ActionType]*BehaviorPattern
	mu       sync.RWMutex
}

func NewBehaviorLearner(config *BrainConfig) *BehaviorLearner {
	return &BehaviorLearner{
		config:   config,
		patterns: make(map[ActionType]*BehaviorPattern),
	}
}

func (bl *BehaviorLearner) RecordOutcome(action *Action, outcome *Outcome) {
	if action == nil || outcome == nil {
		return
	}

	bl.mu.Lock()
	defer bl.mu.Unlock()

	pattern, ok := bl.patterns[action.Type]
	if !ok {
		pattern = &BehaviorPattern{
			ActionType: action.Type,
		}
		bl.patterns[action.Type] = pattern
	}

	total := float64(pattern.Count)
	oldRate := pattern.SuccessRate

	pattern.Count++
	if outcome.Success {
		pattern.SuccessRate = (oldRate*total + 1.0) / float64(pattern.Count)
	} else {
		pattern.SuccessRate = (oldRate * total) / float64(pattern.Count)
	}

	pattern.AvgImpact = (pattern.AvgImpact*total + outcome.Impact) / float64(pattern.Count)
	pattern.LastUsed = time.Now()
}

func (bl *BehaviorLearner) PredictSuccess(action *Action) float64 {
	if action == nil {
		return 0.5
	}

	bl.mu.RLock()
	defer bl.mu.RUnlock()

	pattern, ok := bl.patterns[action.Type]
	if !ok || pattern.Count == 0 {
		return 0.5
	}

	return pattern.SuccessRate
}

func (bl *BehaviorLearner) GetRecommendedAction(context *DecisionContext) *Action {
	if context == nil || len(context.AvailableActions) == 0 {
		return nil
	}

	bl.mu.RLock()
	defer bl.mu.RUnlock()

	var bestAction *Action
	bestScore := -1.0

	for _, action := range context.AvailableActions {
		score := bl.scoreAction(&action)
		if score > bestScore {
			bestScore = score
			bestAction = &action
		}
	}

	return bestAction
}

func (bl *BehaviorLearner) scoreAction(action *Action) float64 {
	pattern, ok := bl.patterns[action.Type]
	if !ok || pattern.Count == 0 {
		return 0.5
	}

	successWeight := pattern.SuccessRate * 0.6
	impactWeight := pattern.AvgImpact * 0.3
	recencyWeight := 0.1

	if !pattern.LastUsed.IsZero() {
		hoursSinceLastUse := time.Since(pattern.LastUsed).Hours()
		if hoursSinceLastUse > 24 {
			recencyWeight = 0.2
		}
	}

	return successWeight + impactWeight + recencyWeight
}

func (bl *BehaviorLearner) GetPatterns() map[ActionType]*BehaviorPattern {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	result := make(map[ActionType]*BehaviorPattern)
	for k, v := range bl.patterns {
		result[k] = v
	}
	return result
}

func (bl *BehaviorLearner) GetPattern(actionType ActionType) (*BehaviorPattern, bool) {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	pattern, ok := bl.patterns[actionType]
	return pattern, ok
}
