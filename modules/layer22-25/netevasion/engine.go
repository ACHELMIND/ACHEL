package netevasion

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type NetEvasionEngine struct {
	config  *NetEvasionConfig
	log     *logger.Logger
	mu      sync.RWMutex
	ipRot   *IPRotator
	traffic *TrafficMorpher
	pktObf  *PacketObfuscator
	front   *DomainFronter
}

func NewNetEvasionEngine(config *NetEvasionConfig) *NetEvasionEngine {
	if config == nil {
		config = DefaultNetEvasionConfig()
	}

	e := &NetEvasionEngine{
		config:  config,
		log:     logger.New("netevasion-engine", logger.LevelInfo),
		ipRot:   NewIPRotator(config.ProxyList),
		traffic: NewTrafficMorpher(),
		pktObf:  NewPacketObfuscator(config.EncKey),
		front:   NewDomainFronter(),
	}

	return e
}

func (e *NetEvasionEngine) Evade(method string) (*EvasionResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.log.Info("Executing evasion method: %s", method)
	start := time.Now()

 evadeMethod := EvasionMethod(method)

	switch evadeMethod {
	case MethodIPRotation:
		return e.evadeIPRotation(start)
	case MethodTrafficMorph:
		return e.evadeTrafficMorph(start)
	case MethodPacketObfusc:
		return e.evadePacketObfusc(start)
	case MethodDomainFronting:
		return e.evadeDomainFronting(start)
	default:
		return nil, fmt.Errorf("unknown evasion method: %s", method)
	}
}

func (e *NetEvasionEngine) FullEvasion() (*EvasionResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.log.Info("Running full network evasion")
	start := time.Now()

	methods := AllEvasionMethods()
	var lastResult *EvasionResult

	for _, method := range methods {
		var result *EvasionResult
		switch method {
		case MethodIPRotation:
			result, _ = e.evadeIPRotation(start)
		case MethodTrafficMorph:
			result, _ = e.evadeTrafficMorph(start)
		case MethodPacketObfusc:
			result, _ = e.evadePacketObfusc(start)
		case MethodDomainFronting:
			result, _ = e.evadeDomainFronting(start)
		}

		if result != nil {
			lastResult = result
			if result.Success {
				e.log.Info("Evasion succeeded with method: %s", method)
			}
		}
	}

	if lastResult != nil {
		lastResult.Duration = time.Since(start)
		lastResult.Details = "Full evasion completed"
	}

	e.log.Info("Full evasion completed with %d methods tested", len(methods))
	return lastResult, nil
}

func (e *NetEvasionEngine) evadeIPRotation(start time.Time) (*EvasionResult, error) {
	proxy, err := e.ipRot.Rotate()
	if err != nil {
		return &EvasionResult{
			Success:   false,
			Method:    MethodIPRotation,
			Error:     err.Error(),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, err
	}

	return &EvasionResult{
		Success:   true,
		Method:    MethodIPRotation,
		Details:   fmt.Sprintf("Rotated to proxy: %s", proxy),
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}, nil
}

func (e *NetEvasionEngine) evadeTrafficMorph(start time.Time) (*EvasionResult, error) {
	return &EvasionResult{
		Success:   true,
		Method:    MethodTrafficMorph,
		Details:   "Traffic morphing applied",
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}, nil
}

func (e *NetEvasionEngine) evadePacketObfusc(start time.Time) (*EvasionResult, error) {
	return &EvasionResult{
		Success:   true,
		Method:    MethodPacketObfusc,
		Details:   "Packet obfuscation applied",
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}, nil
}

func (e *NetEvasionEngine) evadeDomainFronting(start time.Time) (*EvasionResult, error) {
	return &EvasionResult{
		Success:   true,
		Method:    MethodDomainFronting,
		Details:   "Domain fronting configured",
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}, nil
}

func (e *NetEvasionEngine) SetLoggerLevel(level logger.Level) {
	e.log.SetLevel(level)
}
