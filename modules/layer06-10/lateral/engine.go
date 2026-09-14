package lateral

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type LateralEngine struct {
	config  *LateralConfig
	logger  *logger.Logger
	methods map[LateralMethod]LateralMethodImpl
	mu      sync.RWMutex
}

func NewLateralEngine(config *LateralConfig) *LateralEngine {
	if config == nil {
		config = DefaultLateralConfig()
	}

	engine := &LateralEngine{
		config:  config,
		logger:  logger.New("lateral-engine", logger.LevelInfo),
		methods: make(map[LateralMethod]LateralMethodImpl),
	}

	engine.registerMethods()
	return engine
}

func (e *LateralEngine) registerMethods() {
	e.methods[MethodPsExec] = NewPsExecMethod()
	e.methods[MethodSMBExec] = NewSMBExecMethod()
	e.methods[MethodAtExec] = NewAtExecMethod()
	e.methods[MethodWmiExec] = NewWmiExecMethod()
	e.methods[MethodDCOMExec] = NewDCOMExecMethod()
	e.methods[MethodServiceExec] = NewServiceExecMethod()
	e.methods[MethodNamedPipe] = NewNamedPipeMethod()
	e.methods[MethodPassTheHash] = NewPassTheHashMethod()
	e.methods[MethodWinRM] = NewWinRMMethod()
	e.methods[MethodRDP] = NewRDPMethod()
	e.methods[MethodSSH] = NewSSHMethod()
	e.methods[MethodPSRemoting] = NewPSRemotingMethod()
}

func (e *LateralEngine) Execute(method string, target *Target, creds *Credentials) (*LateralResult, error) {
	e.logger.Info("Executing lateral movement via %s to %s", method, target.Host)

	m := LateralMethod(method)
	meth, ok := e.methods[m]
	if !ok {
		return nil, fmt.Errorf("unsupported method: %s", method)
	}

	start := time.Now()
	result, err := meth.Execute(target, creds)
	if err != nil {
		e.logger.Error("Lateral movement failed: %v", err)
		return &LateralResult{
			Success:   false,
			Method:    m,
			Target:    target,
			Error:     err.Error(),
			Duration:  time.Since(start),
			Timestamp: time.Now(),
		}, err
	}

	result.Duration = time.Since(start)
	result.Timestamp = time.Now()
	e.logger.Info("Lateral movement successful via %s in %v", method, result.Duration)
	return result, nil
}

func (e *LateralEngine) ExecuteWithFallback(target *Target, creds *Credentials) (*LateralResult, error) {
	e.logger.Info("Executing lateral movement with fallback chain to %s", target.Host)

	fallbackChain := []LateralMethod{
		MethodPsExec,
		MethodWmiExec,
		MethodWinRM,
		MethodDCOMExec,
		MethodRDP,
		MethodSSH,
		MethodPSRemoting,
	}

	for _, method := range fallbackChain {
		meth, ok := e.methods[method]
		if !ok {
			continue
		}

		if !meth.CanExecute(target, creds) {
			e.logger.Debug("Method %s not applicable, skipping", method)
			continue
		}

		e.logger.Info("Trying method: %s", method)
		result, err := meth.Execute(target, creds)
		if err != nil {
			e.logger.Warn("Method %s failed: %v", method, err)
			continue
		}

		e.logger.Info("Method %s succeeded", method)
		return result, nil
	}

	return nil, fmt.Errorf("all lateral movement methods failed for target %s", target.Host)
}

func (e *LateralEngine) ExecuteChain(methods []LateralMethod, target *Target, creds *Credentials) ([]*LateralResult, error) {
	e.logger.Info("Executing lateral movement chain to %s", target.Host)

	var results []*LateralResult

	for _, method := range methods {
		meth, ok := e.methods[method]
		if !ok {
			return results, fmt.Errorf("unsupported method: %s", method)
		}

		result, err := meth.Execute(target, creds)
		results = append(results, result)

		if err != nil {
			return results, fmt.Errorf("chain failed at method %s: %w", method, err)
		}
	}

	return results, nil
}

func (e *LateralEngine) GetAvailableMethods() []LateralMethod {
	e.mu.RLock()
	defer e.mu.RUnlock()

	methods := make([]LateralMethod, 0, len(e.methods))
	for m := range e.methods {
		methods = append(methods, m)
	}
	return methods
}

func (e *LateralEngine) GetMethod(name string) (LateralMethodImpl, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	m, ok := e.methods[LateralMethod(name)]
	return m, ok
}

func (e *LateralEngine) SetLoggerLevel(level logger.Level) {
	e.logger.SetLevel(level)
}
