package brain

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type Brain struct {
	config    *BrainConfig
	state     *EnvironmentState
	history   []Outcome
	risk      *RiskAssessor
	learner   *BehaviorLearner
	timing    *TimingController
	log       *logger.Logger
	mu        sync.RWMutex
}

func NewBrain(config *BrainConfig) *Brain {
	if config == nil {
		config = DefaultBrainConfig()
	}

	b := &Brain{
		config:  config,
		state:   &EnvironmentState{},
		history: make([]Outcome, 0, config.MaxHistory),
		log:     logger.New("brain", logger.LevelInfo),
	}

	b.risk = NewRiskAssessor()
	b.learner = NewBehaviorLearner(config)
	b.timing = NewTimingController(config)

	return b
}

func (b *Brain) AnalyzeEnvironment(env *EnvironmentState) (*Decision, error) {
	if env == nil {
		return nil, fmt.Errorf("nil environment state")
	}

	b.mu.Lock()
	b.state = env
	b.mu.Unlock()

	b.log.Info("Analyzing environment: %d hosts, %d agents, threat: %.2f",
		env.HostCount, env.AgentCount, env.ThreatLevel)

	decision := &Decision{
		Confidence: ConfidenceMedium,
		RiskScore:  0.5,
		Metadata:   make(map[string]interface{}),
	}

	if env.ThreatLevel > 0.8 {
		decision.Action = Action{
			Type:      ActionTypeEvade,
			Target:    "self",
			RiskLevel: 0.3,
			Timestamp: time.Now(),
		}
		decision.Confidence = ConfidenceHigh
		decision.Reasoning = "High threat level detected, recommending evasion"
		decision.RiskScore = 0.3
	} else if env.HostCount > 10 && env.AgentCount < 3 {
		decision.Action = Action{
			Type:      ActionTypePersist,
			Target:    "network",
			RiskLevel: 0.6,
			Timestamp: time.Now(),
		}
		decision.Confidence = ConfidenceMedium
		decision.Reasoning = "Many hosts available, recommending persistence"
		decision.RiskScore = 0.6
	} else if env.AgentCount > 0 {
		decision.Action = Action{
			Type:      ActionTypeScan,
			Target:    "local",
			RiskLevel: 0.2,
			Timestamp: time.Now(),
		}
		decision.Confidence = ConfidenceLow
		decision.Reasoning = "Agents available, recommending reconnaissance"
		decision.RiskScore = 0.2
	} else {
		decision.Action = Action{
			Type:      ActionTypeWait,
			Target:    "self",
			RiskLevel: 0.1,
			Timestamp: time.Now(),
		}
		decision.Confidence = ConfidenceLow
		decision.Reasoning = "No agents available, waiting"
		decision.RiskScore = 0.1
	}

	return decision, nil
}

func (b *Brain) DecideNextAction(context *DecisionContext) (*Action, error) {
	if context == nil {
		return nil, fmt.Errorf("nil decision context")
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	b.log.Info("Deciding next action with %d available actions", len(context.AvailableActions))

	if len(context.AvailableActions) == 0 {
		return &Action{
			Type:      ActionTypeWait,
			Target:    "self",
			Timestamp: time.Now(),
		}, nil
	}

	bestAction := context.AvailableActions[0]
	bestScore := 0.0

	for _, action := range context.AvailableActions {
		score := b.evaluateAction(&action, context)
		if score > bestScore {
			bestScore = score
			bestAction = action
		}
	}

	return &bestAction, nil
}

func (b *Brain) evaluateAction(action *Action, context *DecisionContext) float64 {
	score := 0.5

	if context.State != nil {
		if action.Type == ActionTypeEvade && context.State.ThreatLevel > 0.7 {
			score += 0.3
		}
		if action.Type == ActionTypeScan && context.State.HostCount > 5 {
			score += 0.2
		}
	}

	if action.RiskLevel < 0.3 {
		score += 0.1
	} else if action.RiskLevel > 0.8 {
		score -= 0.2
	}

	successRate := b.learner.PredictSuccess(action)
	score = (score + successRate) / 2

	return score
}

func (b *Brain) LearnFromHistory(history []Outcome) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.log.Info("Learning from %d outcomes", len(history))

	for _, outcome := range history {
		b.learner.RecordOutcome(&Action{
			ID:   outcome.ActionID,
			Type: outcome.ActionType,
		}, &outcome)
	}

	b.history = append(b.history, history...)
	if len(b.history) > b.config.MaxHistory {
		b.history = b.history[len(b.history)-b.config.MaxHistory:]
	}
}

func (b *Brain) GetHistory() []Outcome {
	b.mu.RLock()
	defer b.mu.RUnlock()

	history := make([]Outcome, len(b.history))
	copy(history, b.history)
	return history
}

func (b *Brain) GetConfig() *BrainConfig {
	return b.config
}

func (b *Brain) GetState() *EnvironmentState {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.state
}
