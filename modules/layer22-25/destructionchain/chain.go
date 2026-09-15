package destructionchain

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
	"github.com/angel-platform/angel/pkg/types"
)

type ChainOrchestrator struct {
	mu      sync.Mutex
	config  *DestructionChainConfig
	timing  *TimingCoordinator
	log     *logger.Logger
	chains  map[string]*DestructionChain
}

func NewChainOrchestrator(config *DestructionChainConfig, timing *TimingCoordinator, log *logger.Logger) *ChainOrchestrator {
	if config == nil {
		config = NewDefaultChainConfig()
	}
	if timing == nil {
		timing = NewTimingCoordinator(NewDefaultTimingConfig())
	}
	if log == nil {
		log = logger.New("chain_orchestrator", logger.LevelInfo)
	}
	return &ChainOrchestrator{
		config: config,
		timing: timing,
		log:    log,
		chains: make(map[string]*DestructionChain),
	}
}

func (c *ChainOrchestrator) BuildChain(steps []ChainStep) *DestructionChain {
	chainID := types.GenerateID()

	for i := range steps {
		if steps[i].ID == "" {
			steps[i].ID = types.GenerateShortID()
		}
		if steps[i].Timeout == 0 {
			steps[i].Timeout = c.config.DefaultTimeout
		}
		if steps[i].Retries == 0 {
			steps[i].Retries = c.config.MaxRetries
		}
		steps[i].Status = StepStatusPending
	}

	chain := &DestructionChain{
		ID:        chainID,
		Name:      fmt.Sprintf("chain-%s", chainID[:8]),
		Status:    ChainStatusPending,
		Steps:     steps,
		CreatedAt: time.Now(),
	}

	c.mu.Lock()
	c.chains[chainID] = chain
	c.mu.Unlock()

	c.log.Info("Built chain %s with %d steps", chainID, len(steps))
	return chain
}

func (c *ChainOrchestrator) ExecuteStep(step *ChainStep) (*StepResult, error) {
	if step == nil {
		return nil, fmt.Errorf("step is nil")
	}

	now := time.Now()
	step.Status = StepStatusRunning
	step.StartedAt = &now

	c.log.Info("Executing step %s (type: %s)", step.ID, step.Type)

	var result *StepResult
	var err error

	for attempt := 0; attempt <= step.Retries; attempt++ {
		result, err = c.executeStepByType(step)
		if err == nil {
			break
		}
		c.log.Warn("Step %s attempt %d failed: %v", step.ID, attempt+1, err)
		if attempt < step.Retries {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}

	completedAt := time.Now()
	step.CompletedAt = &completedAt

	if err != nil {
		step.Status = StepStatusFailed
		step.Error = err.Error()
		return &StepResult{
			Success:   false,
			Error:     err.Error(),
			Timestamp: completedAt,
		}, err
	}

	step.Status = StepStatusCompleted
	return result, nil
}

func (c *ChainOrchestrator) PauseChain(chainID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	chain, ok := c.chains[chainID]
	if !ok {
		return fmt.Errorf("chain %s not found", chainID)
	}

	if chain.Status != ChainStatusRunning {
		return fmt.Errorf("chain %s is not running (status: %s)", chainID, chain.Status)
	}

	chain.Status = ChainStatusPaused
	c.log.Info("Chain %s paused", chainID)
	return nil
}

func (c *ChainOrchestrator) ResumeChain(chainID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	chain, ok := c.chains[chainID]
	if !ok {
		return fmt.Errorf("chain %s not found", chainID)
	}

	if chain.Status != ChainStatusPaused {
		return fmt.Errorf("chain %s is not paused (status: %s)", chainID, chain.Status)
	}

	chain.Status = ChainStatusRunning
	c.log.Info("Chain %s resumed", chainID)
	return nil
}

func (c *ChainOrchestrator) AbortChain(chainID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	chain, ok := c.chains[chainID]
	if !ok {
		return fmt.Errorf("chain %s not found", chainID)
	}

	chain.Status = ChainStatusAborted
	now := time.Now()
	chain.CompletedAt = &now
	c.log.Info("Chain %s aborted", chainID)
	return nil
}

func (c *ChainOrchestrator) executeStepByType(step *ChainStep) (*StepResult, error) {
	now := time.Now()

	switch step.Type {
	case StepTypeRecon:
		return &StepResult{
			Success:   true,
			Data:      map[string]interface{}{"type": "recon", "status": "completed"},
			Timestamp: now,
		}, nil
	case StepTypeScan:
		return &StepResult{
			Success:   true,
			Data:      map[string]interface{}{"type": "scan", "status": "completed"},
			Timestamp: now,
		}, nil
	case StepTypeExploit:
		return &StepResult{
			Success:   true,
			Data:      map[string]interface{}{"type": "exploit", "status": "completed"},
			Timestamp: now,
		}, nil
	case StepTypePivot:
		return &StepResult{
			Success:   true,
			Data:      map[string]interface{}{"type": "pivot", "status": "completed"},
			Timestamp: now,
		}, nil
	case StepTypeEscalate:
		return &StepResult{
			Success:   true,
			Data:      map[string]interface{}{"type": "escalate", "status": "completed"},
			Timestamp: now,
		}, nil
	case StepTypeExfil:
		return &StepResult{
			Success:   true,
			Data:      map[string]interface{}{"type": "exfil", "status": "completed"},
			Timestamp: now,
		}, nil
	case StepTypeDestroy:
		return &StepResult{
			Success:   true,
			Data:      map[string]interface{}{"type": "destroy", "status": "completed"},
			Timestamp: now,
		}, nil
	case StepTypeCleanup:
		return &StepResult{
			Success:   true,
			Data:      map[string]interface{}{"type": "cleanup", "status": "completed"},
			Timestamp: now,
		}, nil
	case StepTypeReport:
		return &StepResult{
			Success:   true,
			Data:      map[string]interface{}{"type": "report", "status": "completed"},
			Timestamp: now,
		}, nil
	default:
		return nil, fmt.Errorf("unknown step type: %s", step.Type)
	}
}
