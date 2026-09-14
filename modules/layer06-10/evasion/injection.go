package evasion

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

var (
	ErrInjectionFailed     = errors.New("injection failed")
	ErrInvalidConfig       = errors.New("invalid injection config")
	ErrProcessNotFound     = errors.New("target process not found")
	ErrAccessDenied        = errors.New("access denied to target process")
	ErrMethodNotSupported  = errors.New("injection method not supported")
	ErrPayloadEmpty        = errors.New("payload is empty")
	ErrInvalidPID          = errors.New("invalid process ID")
)

type CreateRemoteThread struct{}

func NewCreateRemoteThread() *CreateRemoteThread {
	return &CreateRemoteThread{}
}

func (c *CreateRemoteThread) Name() string        { return "CreateRemoteThread" }
func (c *CreateRemoteThread) Category() EvasionCategory { return CategoryInjection }
func (c *CreateRemoteThread) Description() string {
	return "Classic remote thread injection via CreateRemoteThread API"
}

func (c *CreateRemoteThread) Validate(config *InjectionConfig) error {
	if config == nil {
		return ErrInvalidConfig
	}
	if config.TargetPID <= 0 {
		return ErrInvalidPID
	}
	if len(config.Payload) == 0 {
		return ErrPayloadEmpty
	}
	return nil
}

func (c *CreateRemoteThread) Execute(config *InjectionConfig) error {
	if err := c.Validate(config); err != nil {
		return err
	}

	runtimeOS := runtimeGOOS()
	if runtimeOS != "windows" {
		return c.executeLinux(config)
	}
	return c.executeWindows(config)
}

func (c *CreateRemoteThread) executeWindows(config *InjectionConfig) error {
	fmt.Fprintf(os.Stderr, "CreateRemoteThread injection: target=%d, size=%d\n", config.TargetPID, len(config.Payload))
	return nil
}

func (c *CreateRemoteThread) executeLinux(config *InjectionConfig) error {
	fmt.Fprintf(os.Stderr, "ptrace injection: target=%d, size=%d\n", config.TargetPID, len(config.Payload))
	return nil
}

type QueueUserAPC struct{}

func NewQueueUserAPC() *QueueUserAPC {
	return &QueueUserAPC{}
}

func (q *QueueUserAPC) Name() string        { return "QueueUserAPC" }
func (q *QueueUserAPC) Category() EvasionCategory { return CategoryInjection }
func (q *QueueUserAPC) Description() string {
	return "Asynchronous Procedure Call injection via QueueUserAPC"
}

func (q *QueueUserAPC) Validate(config *InjectionConfig) error {
	if config == nil {
		return ErrInvalidConfig
	}
	if config.TargetPID <= 0 {
		return ErrInvalidPID
	}
	if len(config.Payload) == 0 {
		return ErrPayloadEmpty
	}
	return nil
}

func (q *QueueUserAPC) Execute(config *InjectionConfig) error {
	if err := q.Validate(config); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "QueueUserAPC injection: target=%d, size=%d\n", config.TargetPID, len(config.Payload))
	return nil
}

type ProcessHollowing struct{}

func NewProcessHollowing() *ProcessHollowing {
	return &ProcessHollowing{}
}

func (p *ProcessHollowing) Name() string        { return "ProcessHollowing" }
func (p *ProcessHollowing) Category() EvasionCategory { return CategoryInjection }
func (p *ProcessHollowing) Description() string {
	return "Process hollowing: create suspended process, hollow it, and inject payload"
}

func (p *ProcessHollowing) Validate(config *InjectionConfig) error {
	if config == nil {
		return ErrInvalidConfig
	}
	if len(config.Payload) == 0 {
		return ErrPayloadEmpty
	}
	if config.TargetPath == "" {
		return ErrProcessNotFound
	}
	return nil
}

func (p *ProcessHollowing) Execute(config *InjectionConfig) error {
	if err := p.Validate(config); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Process hollowing: target=%s, size=%d\n", config.TargetPath, len(config.Payload))
	return nil
}

type ThreadHijacking struct{}

func NewThreadHijacking() *ThreadHijacking {
	return &ThreadHijacking{}
}

func (t *ThreadHijacking) Name() string        { return "ThreadHijacking" }
func (t *ThreadHijacking) Category() EvasionCategory { return CategoryInjection }
func (t *ThreadHijacking) Description() string {
	return "Hijack existing thread context to redirect execution"
}

func (t *ThreadHijacking) Validate(config *InjectionConfig) error {
	if config == nil {
		return ErrInvalidConfig
	}
	if config.TargetPID <= 0 {
		return ErrInvalidPID
	}
	if len(config.Payload) == 0 {
		return ErrPayloadEmpty
	}
	return nil
}

func (t *ThreadHijacking) Execute(config *InjectionConfig) error {
	if err := t.Validate(config); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Thread hijacking: target=%d, size=%d\n", config.TargetPID, len(config.Payload))
	return nil
}

type ModuleStomping struct{}

func NewModuleStomping() *ModuleStomping {
	return &ModuleStomping{}
}

func (m *ModuleStomping) Name() string        { return "ModuleStomping" }
func (m *ModuleStomping) Category() EvasionCategory { return CategoryInjection }
func (m *ModuleStomping) Description() string {
	return "Overwrite legitimate module in memory with malicious payload"
}

func (m *ModuleStomping) Validate(config *InjectionConfig) error {
	if config == nil {
		return ErrInvalidConfig
	}
	if config.TargetPID <= 0 {
		return ErrInvalidPID
	}
	if len(config.Payload) == 0 {
		return ErrPayloadEmpty
	}
	return nil
}

func (m *ModuleStomping) Execute(config *InjectionConfig) error {
	if err := m.Validate(config); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Module stomping: target=%d, size=%d\n", config.TargetPID, len(config.Payload))
	return nil
}

type ReflectiveDLL struct{}

func NewReflectiveDLL() *ReflectiveDLL {
	return &ReflectiveDLL{}
}

func (r *ReflectiveDLL) Name() string        { return "ReflectiveDLL" }
func (r *ReflectiveDLL) Category() EvasionCategory { return CategoryInjection }
func (r *ReflectiveDLL) Description() string {
	return "Reflective DLL injection: manually load DLL from memory"
}

func (r *ReflectiveDLL) Validate(config *InjectionConfig) error {
	if config == nil {
		return ErrInvalidConfig
	}
	if config.TargetPID <= 0 {
		return ErrInvalidPID
	}
	if len(config.Payload) == 0 {
		return ErrPayloadEmpty
	}
	return nil
}

func (r *ReflectiveDLL) Execute(config *InjectionConfig) error {
	if err := r.Validate(config); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Reflective DLL injection: target=%d, size=%d\n", config.TargetPID, len(config.Payload))
	return nil
}

type SectionMapping struct{}

func NewSectionMapping() *SectionMapping {
	return &SectionMapping{}
}

func (s *SectionMapping) Name() string        { return "SectionMapping" }
func (s *SectionMapping) Category() EvasionCategory { return CategoryInjection }
func (s *SectionMapping) Description() string {
	return "Section mapping injection via shared memory sections"
}

func (s *SectionMapping) Validate(config *InjectionConfig) error {
	if config == nil {
		return ErrInvalidConfig
	}
	if config.TargetPID <= 0 {
		return ErrInvalidPID
	}
	if len(config.Payload) == 0 {
		return ErrPayloadEmpty
	}
	return nil
}

func (s *SectionMapping) Execute(config *InjectionConfig) error {
	if err := s.Validate(config); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Section mapping injection: target=%d, size=%d\n", config.TargetPID, len(config.Payload))
	return nil
}

type InjectionEngine struct {
	methods map[string]InjectionMethod
	mu      sync.RWMutex
	stats   map[string]*InjectionStats
}

type InjectionStats struct {
	Attempts   int
	Successes  int
	Failures   int
	LastUsed   time.Time
}

func NewInjectionEngine() *InjectionEngine {
	engine := &InjectionEngine{
		methods: make(map[string]InjectionMethod),
		stats:   make(map[string]*InjectionStats),
	}
	engine.registerDefaults()
	return engine
}

func (e *InjectionEngine) registerDefaults() {
	e.Register(NewCreateRemoteThread())
	e.Register(NewQueueUserAPC())
	e.Register(NewProcessHollowing())
	e.Register(NewThreadHijacking())
	e.Register(NewModuleStomping())
	e.Register(NewReflectiveDLL())
	e.Register(NewSectionMapping())
}

func (e *InjectionEngine) Register(method InjectionMethod) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.methods[method.Name()] = method
}

func (e *InjectionEngine) GetMethod(name string) (InjectionMethod, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	m, ok := e.methods[name]
	return m, ok
}

func (e *InjectionEngine) Execute(methodName string, config *InjectionConfig) error {
	method, ok := e.GetMethod(methodName)
	if !ok {
		return fmt.Errorf("%w: %s", ErrMethodNotSupported, methodName)
	}

	if err := method.Validate(config); err != nil {
		e.updateStats(methodName, false)
		return err
	}

	if err := method.Execute(config); err != nil {
		e.updateStats(methodName, false)
		return err
	}

	e.updateStats(methodName, true)
	return nil
}

func (e *InjectionEngine) ExecuteWithFallback(config *InjectionConfig) error {
	fallbackOrder := []string{
		"CreateRemoteThread",
		"QueueUserAPC",
		"ProcessHollowing",
		"ThreadHijacking",
		"ModuleStomping",
		"ReflectiveDLL",
		"SectionMapping",
	}

	for _, name := range fallbackOrder {
		method, ok := e.GetMethod(name)
		if !ok {
			continue
		}

		if err := method.Validate(config); err != nil {
			continue
		}

		if err := method.Execute(config); err != nil {
			continue
		}

		e.updateStats(name, true)
		return nil
	}

	return ErrInjectionFailed
}

func (e *InjectionEngine) GetStats() map[string]*InjectionStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	stats := make(map[string]*InjectionStats, len(e.stats))
	for k, v := range e.stats {
		stats[k] = &InjectionStats{
			Attempts:  v.Attempts,
			Successes: v.Successes,
			Failures:  v.Failures,
			LastUsed:  v.LastUsed,
		}
	}
	return stats
}

func (e *InjectionEngine) updateStats(methodName string, success bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	stats, ok := e.stats[methodName]
	if !ok {
		stats = &InjectionStats{}
		e.stats[methodName] = stats
	}

	stats.Attempts++
	if success {
		stats.Successes++
	} else {
		stats.Failures++
	}
	stats.LastUsed = time.Now()
}

func (e *InjectionEngine) ListMethods() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	names := make([]string, 0, len(e.methods))
	for name := range e.methods {
		names = append(names, name)
	}
	return names
}

func (e *InjectionEngine) GetSuccessRate(methodName string) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	stats, ok := e.stats[methodName]
	if !ok || stats.Attempts == 0 {
		return 0.0
	}
	return float64(stats.Successes) / float64(stats.Attempts)
}

func runtimeGOOS() string {
	return runtime.GOOS
}

func unsafeSlice(ptr unsafe.Pointer, size uintptr) []byte {
	return unsafe.Slice((*byte)(ptr), size)
}
