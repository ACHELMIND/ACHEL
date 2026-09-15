package destructionchain

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
	"github.com/angel-platform/angel/pkg/types"
)

type DestructionChainEngine struct {
	mu          sync.Mutex
	config      *DestructionChainConfig
	orchestrator *ChainOrchestrator
	timing      *TimingCoordinator
	log         *logger.Logger
	chains      map[string]*DestructionChain
}

func NewDestructionChainEngine(config *DestructionChainConfig) *DestructionChainEngine {
	if config == nil {
		config = NewDefaultChainConfig()
	}
	l := logger.New("destructionchain", logger.LevelInfo)
	tc := NewTimingCoordinator(NewDefaultTimingConfig())
	co := NewChainOrchestrator(config, tc, l)

	return &DestructionChainEngine{
		config:       config,
		orchestrator: co,
		timing:       tc,
		log:          l,
		chains:       make(map[string]*DestructionChain),
	}
}

func (e *DestructionChainEngine) FullScopeAttack(target *FullScopeTarget) (*FullScopeResult, error) {
	if target == nil {
		return nil, fmt.Errorf("target is nil")
	}

	start := time.Now()
	chainID := types.GenerateID()

	e.log.Info("Starting full scope attack on %s", target.Host)

	recon, err := e.executeRecon(target)
	if err != nil {
		return nil, fmt.Errorf("recon failed: %w", err)
	}

	attack, err := e.executeAttack(target, recon)
	if err != nil {
		return nil, fmt.Errorf("attack failed: %w", err)
	}

	destroy, err := e.executeDestroy(target, attack)
	if err != nil {
		e.log.Error("Destroy phase failed: %v", err)
	}

	report := e.generateReport(target, recon, attack, destroy)

	duration := time.Since(start)
	result := &FullScopeResult{
		ChainID:        chainID,
		Target:         target,
		Recon:          recon,
		Attack:         attack,
		Destroy:        destroy,
		Report:         report,
		OverallSuccess: attack.Exploited,
		Duration:       duration,
		Timestamp:      time.Now(),
	}

	e.log.Info("Full scope attack completed on %s in %v", target.Host, duration)
	return result, nil
}

func (e *DestructionChainEngine) ExecuteChain(chain *DestructionChain) (*ChainResult, error) {
	if chain == nil {
		return nil, fmt.Errorf("chain is nil")
	}

	e.mu.Lock()
	e.chains[chain.ID] = chain
	e.mu.Unlock()

	start := time.Now()
	chain.Status = ChainStatusRunning
	now := time.Now()
	chain.StartedAt = &now

	e.log.Info("Executing chain %s with %d steps", chain.ID, len(chain.Steps))

	results := make(map[string]*StepResult)
	for i := range chain.Steps {
		step := &chain.Steps[i]

		if e.config.PauseOnError && step.Status == StepStatusFailed {
			chain.Status = ChainStatusPaused
			e.log.Warn("Chain paused at step %s due to error", step.ID)
			break
		}

		result, err := e.orchestrator.ExecuteStep(step)
		if err != nil {
			e.log.Error("Step %s failed: %v", step.ID, err)
			if e.config.PauseOnError {
				chain.Status = ChainStatusPaused
				break
			}
			continue
		}
		results[step.ID] = result
	}

	completedAt := time.Now()
	chain.CompletedAt = &completedAt
	chain.Status = ChainStatusCompleted

	return &ChainResult{
		ChainID:     chain.ID,
		Success:     true,
		Results:     results,
		StartedAt:   start,
		CompletedAt: completedAt,
		Duration:    completedAt.Sub(start),
	}, nil
}

func (e *DestructionChainEngine) CalculateImpact(target string) (*ImpactReport, error) {
	if target == "" {
		return nil, fmt.Errorf("target is empty")
	}

	criticality := types.SeverityHigh
	riskScore := 0.7

	return &ImpactReport{
		Target:          target,
		Scope:           "full",
		Criticality:     criticality,
		AffectedHosts:   1,
		EstimatedTime:   30 * time.Minute,
		RiskScore:       riskScore,
		Recommendations: []string{"Isolate target", "Collect evidence", "Document all actions"},
	}, nil
}

func (e *DestructionChainEngine) EstimateCompletionTime(chain *DestructionChain) time.Duration {
	if chain == nil || len(chain.Steps) == 0 {
		return 0
	}

	var total time.Duration
	for _, step := range chain.Steps {
		if step.Status == StepStatusCompleted {
			if step.StartedAt != nil && step.CompletedAt != nil {
				total += step.CompletedAt.Sub(*step.StartedAt)
			}
			continue
		}
		total += e.config.DefaultTimeout
	}
	return total
}

func (e *DestructionChainEngine) executeRecon(target *FullScopeTarget) (*ReconResult, error) {
	result := &ReconResult{
		Host:       target.Host,
		Ports:      target.Services,
		Vulns:      target.Vulns,
		Secrets:    []string{},
		NetworkMap: make(map[string]interface{}),
	}
	result.NetworkMap["host"] = target.Host
	result.NetworkMap["ip"] = target.IP
	result.NetworkMap["os"] = string(target.OS)
	return result, nil
}

func (e *DestructionChainEngine) executeAttack(target *FullScopeTarget, recon *ReconResult) (*AttackResult, error) {
	result := &AttackResult{
		Exploited: len(recon.Vulns) > 0,
		Access:    "user",
		Creds:     target.Creds,
		Shells:    []ShellInfo{},
		Data:      make(map[string]interface{}),
	}
	if result.Exploited {
		result.Shells = append(result.Shells, ShellInfo{
			Type: "reverse",
			Host: target.IP,
			Port: 4444,
		})
	}
	return result, nil
}

func (e *DestructionChainEngine) executeDestroy(target *FullScopeTarget, attack *AttackResult) (*DestroyResult, error) {
	result := &DestroyResult{
		Target:    target.Host,
		Method:    "data_wipe",
		Artifacts: []string{},
		Verified:  false,
	}
	return result, nil
}

func (e *DestructionChainEngine) generateReport(target *FullScopeTarget, recon *ReconResult, attack *AttackResult, destroy *DestroyResult) *types.ModuleResult {
	return &types.ModuleResult{
		Module:    "destructionchain",
		Success:   attack.Exploited,
		Data: map[string]interface{}{
			"target":  target.Host,
			"recon":   recon,
			"attack":  attack,
			"destroy": destroy,
		},
		Timestamp: time.Now(),
	}
}
