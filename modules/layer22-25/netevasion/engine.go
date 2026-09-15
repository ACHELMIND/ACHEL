package netevasion

import (
	"fmt"
	"net/http"
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
	// Build a synthetic request and morph it through all traffic morpher stages.
	sampleReq, err := http.NewRequest("POST", "https://example.com/api/v1/telemetry", nil)
	if err != nil {
		return &EvasionResult{
			Success:   false,
			Method:    MethodTrafficMorph,
			Error:     fmt.Sprintf("create sample request: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, err
	}
	sampleReq.Header.Set("X-Forwarded-For", "10.0.0.1")
	sampleReq.Header.Set("X-Real-IP", "192.168.1.1")

	// Stage 1: HTTP/2 fingerprint morphing (randomises UA, strips identifying headers).
	morphedReq := e.traffic.MorphHTTP2Fingerprint(sampleReq)
	if morphedReq == nil {
		return &EvasionResult{
			Success:   false,
			Method:    MethodTrafficMorph,
			Error:     "MorphHTTP2Fingerprint returned nil",
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, fmt.Errorf("morph HTTP2 returned nil")
	}

	// Stage 2: Header randomisation.
	morphedReq.Header = e.traffic.RandomizeHeaders(morphedReq.Header)

	// Stage 3: Sleep jitter (non-blocking when jitter is 0).
	sampleData := []byte("exfil-payload")
	jitteredData := e.traffic.AddSleepJitter(sampleData, e.config.JitterPercent)

	// Stage 4: Packet size morphing.
	samplePackets := [][]byte{
		[]byte("packet-1"),
		[]byte("packet-2"),
		[]byte("packet-3"),
	}
	morphedPackets := e.traffic.MorphPacketSizes(samplePackets)

	details := fmt.Sprintf(
		"HTTP/2 fingerprint morphed (UA: %s), headers randomised, jitter %.0f%% applied, %d packets resized",
		morphedReq.Header.Get("User-Agent"),
		e.config.JitterPercent*100,
		len(morphedPackets),
	)
	_ = jitteredData // success indicator — AddSleepJitter returns data

	return &EvasionResult{
		Success:   true,
		Method:    MethodTrafficMorph,
		Details:   details,
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}, nil
}

func (e *NetEvasionEngine) evadePacketObfusc(start time.Time) (*EvasionResult, error) {
	// Demonstrate real encryption/encoding round-trip through the packet obfuscator.
	samplePayload := []byte("ANGEL_C2_BEACON_CHECKIN_PAYLOAD_v1")

	obfuscated, err := e.pktObf.ObfuscatePayload(samplePayload)
	if err != nil {
		return &EvasionResult{
			Success:   false,
			Method:    MethodPacketObfusc,
			Error:     fmt.Sprintf("obfuscate: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, fmt.Errorf("obfuscate payload: %w", err)
	}

	deobfuscated, err := e.pktObf.DeobfuscatePayload(obfuscated)
	if err != nil {
		return &EvasionResult{
			Success:   false,
			Method:    MethodPacketObfusc,
			Error:     fmt.Sprintf("deobfuscate: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, fmt.Errorf("deobfuscate payload: %w", err)
	}

	if string(deobfuscated) != string(samplePayload) {
		return &EvasionResult{
			Success:   false,
			Method:    MethodPacketObfusc,
			Error:     "round-trip integrity check failed",
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, fmt.Errorf("round-trip mismatch")
	}

	details := fmt.Sprintf(
		"AES-256-GCM encrypted + base64 encoded: %d bytes -> %d bytes (round-trip verified)",
		len(samplePayload), len(obfuscated),
	)

	return &EvasionResult{
		Success:   true,
		Method:    MethodPacketObfusc,
		Details:   details,
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}, nil
}

func (e *NetEvasionEngine) evadeDomainFronting(start time.Time) (*EvasionResult, error) {
	// If a target CDN is configured, register it and test the connection.
	frontName := "primary-front"
	if e.config.TargetCDN != "" {
		frontCfg := &DomainFrontConfig{
			Target:   "https://" + e.config.TargetCDN,
			CDN:      e.config.TargetCDN,
			Host:     e.config.TargetCDN,
			Protocol: "https",
		}
		e.front.AddFront(frontName, frontCfg)
	}

	// Ensure at least one front exists for testing.  When no CDN is configured
	// we register a sensible default so the method still exercises real logic.
	_, exists := e.front.GetFront(frontName)
	if !exists {
		defaultCfg := &DomainFrontConfig{
			Target:   "https://example.com",
			CDN:      "cloudfront.net",
			Host:     "d111111abcdef8.cloudfront.net",
			Protocol: "https",
		}
		e.front.AddFront(frontName, defaultCfg)
	}

	connResult, err := e.front.TestConnection(frontName)
	if err != nil {
		return &EvasionResult{
			Success:   false,
			Method:    MethodDomainFronting,
			Error:     fmt.Sprintf("test connection: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, fmt.Errorf("domain front test: %w", err)
	}

	headers, err := e.front.BuildHTTPRequest(frontName)
	if err != nil {
		return &EvasionResult{
			Success:   false,
			Method:    MethodDomainFronting,
			Error:     fmt.Sprintf("build request: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, fmt.Errorf("domain front build request: %w", err)
	}

	details := fmt.Sprintf(
		"Front '%s' configured: %s | Host header: %s | %s",
		frontName, connResult.RequestStr, headers["Host"], "connection verified",
	)

	return &EvasionResult{
		Success:   true,
		Method:    MethodDomainFronting,
		Details:   details,
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}, nil
}

func (e *NetEvasionEngine) SetLoggerLevel(level logger.Level) {
	e.log.SetLevel(level)
}
