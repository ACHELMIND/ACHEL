package evasion

import (
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

type AntiAnalysisEngine struct {
	debuggers  []AntiDetector
	vms        []AntiDetector
	sandboxes  []AntiDetector
	mu         sync.RWMutex
	config     *AntiAnalysisConfig
}

type AntiAnalysisConfig struct {
	EnableDebuggerChecks  bool
	EnableVMChecks        bool
	EnableSandboxChecks   bool
	StrictMode            bool
}

func NewAntiAnalysisEngine() *AntiAnalysisEngine {
	engine := &AntiAnalysisEngine{
		config: &AntiAnalysisConfig{
			EnableDebuggerChecks: true,
			EnableVMChecks:       true,
			EnableSandboxChecks:  true,
			StrictMode:           false,
		},
	}
	engine.registerDefaults()
	return engine
}

func (e *AntiAnalysisEngine) registerDefaults() {
	e.debuggers = append(e.debuggers,
		&IsDebuggerPresent{},
		&CheckRemoteDebugger{},
		&NtGlobalFlag{},
		&HardwareBPCheck{},
		&TimingRDTSC{},
	)
	e.vms = append(e.vms,
		&CPUIDHypervisor{},
		&MACAddressPrefix{},
		&RegistryKeys{},
		&DeviceDrivers{},
		&ProcessCheck{},
	)
	e.sandboxes = append(e.sandboxes,
		&UptimeCheck{},
		&MouseNoMovement{},
		&DiskSizeCheck{},
		&CoreCountCheck{},
		&RAMSizeCheck{},
	)
}

func (e *AntiAnalysisEngine) RunAll() []DetectionResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var results []DetectionResult

	if e.config.EnableDebuggerChecks {
		for _, det := range e.debuggers {
			results = append(results, det.Detect())
		}
	}
	if e.config.EnableVMChecks {
		for _, det := range e.vms {
			results = append(results, det.Detect())
		}
	}
	if e.config.EnableSandboxChecks {
		for _, det := range e.sandboxes {
			results = append(results, det.Detect())
		}
	}
	return results
}

func (e *AntiAnalysisEngine) RunDebuggerChecks() []DetectionResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var results []DetectionResult
	for _, det := range e.debuggers {
		results = append(results, det.Detect())
	}
	return results
}

func (e *AntiAnalysisEngine) RunVMChecks() []DetectionResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var results []DetectionResult
	for _, det := range e.vms {
		results = append(results, det.Detect())
	}
	return results
}

func (e *AntiAnalysisEngine) RunSandboxChecks() []DetectionResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var results []DetectionResult
	for _, det := range e.sandboxes {
		results = append(results, det.Detect())
	}
	return results
}

func (e *AntiAnalysisEngine) IsAnalyzed() bool {
	results := e.RunAll()
	for _, r := range results {
		if r.Detected && r.RiskScore > 0.5 {
			return true
		}
	}
	return false
}

func (e *AntiAnalysisEngine) GenerateReport() *EvasionReport {
	report := &EvasionReport{
		Module:    "AntiAnalysis",
		Timestamp: time.Now(),
	}
	for _, r := range e.RunAll() {
		report.AddResult(r)
	}
	return report
}

type IsDebuggerPresent struct{}

func (d *IsDebuggerPresent) Name() string       { return "IsDebuggerPresent" }
func (d *IsDebuggerPresent) Category() DetectionType { return DetectionDebugger }

func (d *IsDebuggerPresent) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionDebugger,
		Method:    "IsDebuggerPresent",
		Timestamp: time.Now(),
	}

	debuggerPresent := isDebuggerPresentLow()
	result.Detected = debuggerPresent
	if debuggerPresent {
		result.Details = "Debugger detected via IsDebuggerPresent API"
		result.RiskScore = 0.9
	} else {
		result.Details = "No debugger detected"
		result.RiskScore = 0.0
	}
	return result
}

func isDebuggerPresentLow() bool {
	for _, arg := range os.Args {
		if strings.Contains(arg, "gdb") || strings.Contains(arg, "lldb") {
			return true
		}
	}
	ppid := os.Getppid()
	if ppid == 1 {
		return false
	}
	tracePIDPath := fmt.Sprintf("/proc/%d/status", os.Getpid())
	if data, err := os.ReadFile(tracePIDPath); err == nil {
		content := string(data)
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(line, "TracerPid:") {
				pid := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
				if pid != "0" {
					return true
				}
			}
		}
	}
	return false
}

type CheckRemoteDebugger struct{}

func (d *CheckRemoteDebugger) Name() string       { return "CheckRemoteDebugger" }
func (d *CheckRemoteDebugger) Category() DetectionType { return DetectionDebugger }

func (d *CheckRemoteDebugger) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionDebugger,
		Method:    "CheckRemoteDebugger",
		Timestamp: time.Now(),
	}

	detected := checkRemoteDebuggerLow()
	result.Detected = detected
	if detected {
		result.Details = "Remote debugger detected"
		result.RiskScore = 0.85
	} else {
		result.Details = "No remote debugger detected"
		result.RiskScore = 0.0
	}
	return result
}

func checkRemoteDebuggerLow() bool {
	statusPath := fmt.Sprintf("/proc/%d/status", os.Getppid())
	if data, err := os.ReadFile(statusPath); err == nil {
		content := string(data)
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(line, "Name:") {
				name := strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
				if strings.Contains(name, "gdb") || strings.Contains(name, "strace") || strings.Contains(name, "ltrace") {
					return true
				}
			}
		}
	}
	return false
}

type NtGlobalFlag struct{}

func (d *NtGlobalFlag) Name() string       { return "NtGlobalFlag" }
func (d *NtGlobalFlag) Category() DetectionType { return DetectionDebugger }

func (d *NtGlobalFlag) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionDebugger,
		Method:    "NtGlobalFlag",
		Timestamp: time.Now(),
	}

	detected := ntGlobalFlagCheck()
	result.Detected = detected
	if detected {
		result.Details = "NtGlobalFlag indicates debugger present"
		result.RiskScore = 0.7
	} else {
		result.Details = "NtGlobalFlag check clean"
		result.RiskScore = 0.0
	}
	return result
}

func ntGlobalFlagCheck() bool {
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "GOFLAGS=") {
			flags := strings.TrimPrefix(env, "GOFLAGS=")
			if strings.Contains(flags, "-gcflags") {
				return true
			}
		}
	}
	if os.Getenv("GOFLAGS") != "" {
		return strings.Contains(os.Getenv("GOFLAGS"), "d")
	}
	return false
}

type HardwareBPCheck struct{}

func (d *HardwareBPCheck) Name() string       { return "HardwareBPCheck" }
func (d *HardwareBPCheck) Category() DetectionType { return DetectionDebugger }

func (d *HardwareBPCheck) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionDebugger,
		Method:    "HardwareBPCheck",
		Timestamp: time.Now(),
	}

	detected := hardwareBPCheck()
	result.Detected = detected
	if detected {
		result.Details = "Hardware breakpoints detected"
		result.RiskScore = 0.75
	} else {
		result.Details = "No hardware breakpoints detected"
		result.RiskScore = 0.0
	}
	return result
}

func hardwareBPCheck() bool {
	if runtime.GOARCH != "amd64" {
		return false
	}
	bpCount := 0
	for i := 0; i < 4; i++ {
		if bpAddr := getDebugRegister(i); bpAddr != 0 {
			bpCount++
		}
	}
	return bpCount > 0
}

func getDebugRegister(reg int) uintptr {
	var addr uintptr
	_ = reg
	_ = addr
	return 0
}

type TimingRDTSC struct{}

func (d *TimingRDTSC) Name() string       { return "TimingRDTSC" }
func (d *TimingRDTSC) Category() DetectionType { return DetectionDebugger }

func (d *TimingRDTSC) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionDebugger,
		Method:    "TimingRDTSC",
		Timestamp: time.Now(),
	}

	start := time.Now()
busyWork := 0
	for i := 0; i < 1000000; i++ {
		busyWork += i
	}
	elapsed := time.Since(start)
	_ = busyWork

	detected := elapsed > 500*time.Millisecond
	result.Detected = detected
	if detected {
		result.Details = fmt.Sprintf("Timing anomaly detected: %v (possible debugger slowdown)", elapsed)
		result.RiskScore = 0.6
	} else {
		result.Details = "Timing check normal"
		result.RiskScore = 0.0
	}
	return result
}

type CPUIDHypervisor struct{}

func (d *CPUIDHypervisor) Name() string       { return "CPUIDHypervisor" }
func (d *CPUIDHypervisor) Category() DetectionType { return DetectionVM }

func (d *CPUIDHypervisor) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionVM,
		Method:    "CPUIDHypervisor",
		Timestamp: time.Now(),
	}

	detected := cpuidHypervisorCheck()
	result.Detected = detected
	if detected {
		result.Details = "CPUID hypervisor bit set"
		result.RiskScore = 0.8
	} else {
		result.Details = "No hypervisor detected via CPUID"
		result.RiskScore = 0.0
	}
	return result
}

func cpuidHypervisorCheck() bool {
	vendorHints := []string{
		"VBoxVBoxVBox",
		"Microsoft Hv",
		"VMwareVMware",
		"KVMKVMKVM",
		"XenVMMXenVMM",
		"TCGTCGTCGTCG",
	}

	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	content := string(data)
	for _, vendor := range vendorHints {
		if strings.Contains(content, vendor) {
			return true
		}
	}

	dmiPath := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
	}
	for _, path := range dmiPath {
		if dmiData, err := os.ReadFile(path); err == nil {
			dmiStr := strings.ToLower(string(dmiData))
			for _, v := range []string{"virtual", "vmware", "virtualbox", "qemu", "xen", "kvm"} {
				if strings.Contains(dmiStr, v) {
					return true
				}
			}
		}
	}
	return false
}

type MACAddressPrefix struct{}

func (d *MACAddressPrefix) Name() string       { return "MACAddressPrefix" }
func (d *MACAddressPrefix) Category() DetectionType { return DetectionVM }

func (d *MACAddressPrefix) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionVM,
		Method:    "MACAddressPrefix",
		Timestamp: time.Now(),
	}

	data, err := os.ReadFile("/sys/class/net/eth0/address")
	if err != nil {
		result.Detected = false
		result.Details = "Could not read MAC address"
		result.RiskScore = 0.0
		return result
	}

	mac := strings.TrimSpace(string(data))
	vmPrefixes := []string{
		"00:50:56",
		"00:0C:29",
		"00:05:69",
		"08:00:27",
		"52:54:00",
		"00:16:3E",
		"00:15:5D",
		"00:1C:14",
		"00:03:FF",
		"0A:00:27",
	}

	detected := false
	for _, prefix := range vmPrefixes {
		if strings.HasPrefix(mac, prefix) {
			detected = true
			break
		}
	}

	result.Detected = detected
	if detected {
		result.Details = fmt.Sprintf("VM MAC prefix detected: %s", mac[:8])
		result.RiskScore = 0.7
	} else {
		result.Details = "MAC address appears to be physical"
		result.RiskScore = 0.0
	}
	return result
}

type RegistryKeys struct{}

func (d *RegistryKeys) Name() string       { return "RegistryKeys" }
func (d *RegistryKeys) Category() DetectionType { return DetectionVM }

func (d *RegistryKeys) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionVM,
		Method:    "RegistryKeys",
		Timestamp: time.Now(),
	}

	if runtime.GOOS != "linux" {
		result.Detected = false
		result.Details = "Registry check skipped on non-Windows OS"
		result.RiskScore = 0.0
		return result
	}

	dmiPaths := []string{
		"/sys/class/dmi/id/chassis_asset_tag",
		"/sys/class/dmi/id/board_name",
		"/sys/class/dmi/id/bios_vendor",
	}

	vmStrings := []string{"virtual", "vmware", "virtualbox", "qemu", "xen", "kvm", "parallels"}
	detected := false

	for _, path := range dmiPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := strings.ToLower(string(data))
		for _, vmStr := range vmStrings {
			if strings.Contains(content, vmStr) {
				detected = true
				result.Details = fmt.Sprintf("VM string found at %s: %s", path, strings.TrimSpace(string(data)))
				break
			}
		}
		if detected {
			break
		}
	}

	result.Detected = detected
	if detected {
		result.RiskScore = 0.75
	} else {
		result.Details = "No VM-related DMI strings found"
		result.RiskScore = 0.0
	}
	return result
}

type DeviceDrivers struct{}

func (d *DeviceDrivers) Name() string       { return "DeviceDrivers" }
func (d *DeviceDrivers) Category() DetectionType { return DetectionVM }

func (d *DeviceDrivers) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionVM,
		Method:    "DeviceDrivers",
		Timestamp: time.Now(),
	}

	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		result.Detected = false
		result.Details = "Could not read /proc/modules"
		result.RiskScore = 0.0
		return result
	}

	content := strings.ToLower(string(data))
	vmDrivers := []string{
		"vmw_balloon",
		"vmmemctl",
		"vboxguest",
		"vboxsf",
		"vboxvideo",
		"virtio_pci",
		"virtio_net",
		"virtio_blk",
		"hv_vmbus",
		"hv_storvsc",
		"hv_netvsc",
		"xen_blkfront",
		"xen_netfront",
		"qxl",
		"bochs_drm",
	}

	detected := false
	for _, driver := range vmDrivers {
		if strings.Contains(content, driver) {
			detected = true
			result.Details = fmt.Sprintf("VM driver loaded: %s", driver)
			break
		}
	}

	result.Detected = detected
	if detected {
		result.RiskScore = 0.65
	} else {
		result.Details = "No VM-related drivers detected"
		result.RiskScore = 0.0
	}
	return result
}

type ProcessCheck struct{}

func (d *ProcessCheck) Name() string       { return "ProcessCheck" }
func (d *ProcessCheck) Category() DetectionType { return DetectionVM }

func (d *ProcessCheck) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionVM,
		Method:    "ProcessCheck",
		Timestamp: time.Now(),
	}

	vmProcesses := []string{
		"vmtoolsd",
		"vmware",
		"vboxservice",
		"vboxtray",
		"qemu-ga",
		"spice-vdagentd",
		"vdagent",
		"xenstored",
		"xe-daemon",
		"pvscsi",
		"hyperkvp",
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		result.Detected = false
		result.Details = "Could not read /proc"
		result.RiskScore = 0.0
		return result
	}

	detected := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		cmdlinePath := fmt.Sprintf("/proc/%s/cmdline", entry.Name())
		data, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}
		content := strings.ToLower(string(data))
		for _, proc := range vmProcesses {
			if strings.Contains(content, proc) {
				detected = true
				result.Details = fmt.Sprintf("VM process detected: %s", proc)
				break
			}
		}
		if detected {
			break
		}
	}

	result.Detected = detected
	if detected {
		result.RiskScore = 0.6
	} else {
		result.Details = "No VM-related processes detected"
		result.RiskScore = 0.0
	}
	return result
}

type UptimeCheck struct{}

func (d *UptimeCheck) Name() string       { return "UptimeCheck" }
func (d *UptimeCheck) Category() DetectionType { return DetectionSandbox }

func (d *UptimeCheck) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionSandbox,
		Method:    "UptimeCheck",
		Timestamp: time.Now(),
	}

	uptimeData, err := os.ReadFile("/proc/uptime")
	if err != nil {
		result.Detected = false
		result.Details = "Could not read uptime"
		result.RiskScore = 0.0
		return result
	}

	var uptime float64
	fmt.Sscanf(string(uptimeData), "%f", &uptime)

	detected := uptime < 300.0
	result.Detected = detected
	if detected {
		result.Details = fmt.Sprintf("System uptime too low: %.1f seconds (possible sandbox)", uptime)
		result.RiskScore = 0.7
	} else {
		result.Details = fmt.Sprintf("System uptime: %.1f seconds", uptime)
		result.RiskScore = 0.0
	}
	return result
}

type MouseNoMovement struct{}

func (d *MouseNoMovement) Name() string       { return "MouseNoMovement" }
func (d *MouseNoMovement) Category() DetectionType { return DetectionSandbox }

func (d *MouseNoMovement) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionSandbox,
		Method:    "MouseNoMovement",
		Timestamp: time.Now(),
	}

	inputPath := "/dev/input"
	detected := false
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		result.Detected = false
		result.Details = "No input devices (possible headless sandbox)"
		result.RiskScore = 0.4
		return result
	}

	events, err := os.ReadDir(inputPath)
	if err != nil || len(events) == 0 {
		detected = true
		result.Details = "No input devices available"
		result.RiskScore = 0.4
	}

	result.Detected = detected
	if !detected {
		result.Details = "Input devices present"
		result.RiskScore = 0.0
	}
	return result
}

type DiskSizeCheck struct{}

func (d *DiskSizeCheck) Name() string       { return "DiskSizeCheck" }
func (d *DiskSizeCheck) Category() DetectionType { return DetectionSandbox }

func (d *DiskSizeCheck) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionSandbox,
		Method:    "DiskSizeCheck",
		Timestamp: time.Now(),
	}

	totalBytes, err := getDiskTotalBytes("/")
	if err != nil {
		result.Detected = false
		result.Details = "Could not get disk stats"
		result.RiskScore = 0.0
		return result
	}

	totalGB := float64(totalBytes) / (1024 * 1024 * 1024)

	detected := totalGB < 50.0
	result.Detected = detected
	if detected {
		result.Details = fmt.Sprintf("Disk size too small: %.1f GB (possible sandbox)", totalGB)
		result.RiskScore = 0.5
	} else {
		result.Details = fmt.Sprintf("Disk size: %.1f GB", totalGB)
		result.RiskScore = 0.0
	}
	return result
}

func getDiskTotalBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Blocks * uint64(stat.Bsize), nil
}

type CoreCountCheck struct{}

func (d *CoreCountCheck) Name() string       { return "CoreCountCheck" }
func (d *CoreCountCheck) Category() DetectionType { return DetectionSandbox }

func (d *CoreCountCheck) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionSandbox,
		Method:    "CoreCountCheck",
		Timestamp: time.Now(),
	}

	cores := runtime.NumCPU()
	detected := cores < 2
	result.Detected = detected
	if detected {
		result.Details = fmt.Sprintf("CPU core count too low: %d (possible sandbox)", cores)
		result.RiskScore = 0.5
	} else {
		result.Details = fmt.Sprintf("CPU cores: %d", cores)
		result.RiskScore = 0.0
	}
	return result
}

type RAMSizeCheck struct{}

func (d *RAMSizeCheck) Name() string       { return "RAMSizeCheck" }
func (d *RAMSizeCheck) Category() DetectionType { return DetectionSandbox }

func (d *RAMSizeCheck) Detect() DetectionResult {
	result := DetectionResult{
		Type:      DetectionSandbox,
		Method:    "RAMSizeCheck",
		Timestamp: time.Now(),
	}

	memInfo, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		result.Detected = false
		result.Details = "Could not read memory info"
		result.RiskScore = 0.0
		return result
	}

	var totalMemKB uint64
	for _, line := range strings.Split(string(memInfo), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fmt.Sscanf(strings.TrimPrefix(line, "MemTotal:"), "%d kB", &totalMemKB)
			break
		}
	}

	totalGB := float64(totalMemKB) / (1024 * 1024)
	detected := totalGB < 2.0
	result.Detected = detected
	if detected {
		result.Details = fmt.Sprintf("RAM too low: %.1f GB (possible sandbox)", totalGB)
		result.RiskScore = 0.5
	} else {
		result.Details = fmt.Sprintf("RAM: %.1f GB", totalGB)
		result.RiskScore = 0.0
	}
	return result
}

func currentUser() string {
	u, err := user.Current()
	if err != nil {
		return "unknown"
	}
	return u.Username
}

func isCommonVMUser() bool {
	vmUsers := []string{
		"sandbox",
		"malware",
		"virus",
		"test",
		"user",
		"admin",
		"john",
		"jane",
		"susan",
		"peter",
	}
	username := strings.ToLower(currentUser())
	for _, u := range vmUsers {
		if username == u {
			return true
		}
	}
	return false
}

func generateHash(input string) string {
	h := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", h)
}

func detectEnvironmentFingerprint() string {
	fingerprint := fmt.Sprintf("%s-%s-%s-%d",
		runtime.GOOS,
		runtime.GOARCH,
		currentUser(),
		time.Now().UnixNano(),
	)
	return generateHash(fingerprint)[:16]
}

func calculateRiskScore(results []DetectionResult) float64 {
	if len(results) == 0 {
		return 0.0
	}
	total := 0.0
	count := 0
	for _, r := range results {
		if r.Detected {
			total += r.RiskScore
			count++
		}
	}
	if count == 0 {
		return 0.0
	}
	return math.Min(total/float64(count), 1.0)
}
