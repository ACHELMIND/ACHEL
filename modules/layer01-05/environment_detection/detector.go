package environment_detection

import (
	"os"
	"runtime"
	"sync"
)

type EnvironmentDetector struct {
	mu           sync.RWMutex
环境信息      *EnvironmentInfo
	detected     bool
}

type EnvironmentInfo struct {
	OS           string
	Arch         string
	Hostname     string
	IsVM         bool
	IsSandbox    bool
	IsDebugged   bool
	IsContainer  bool
	VMType       string
	SandboxType  string
	CPUCores     int
	RAMMB        int
	DiskGB       int
	UptimeMin    int
}

func NewEnvironmentDetector() *EnvironmentDetector {
	return &EnvironmentDetector{
		环境信息: &EnvironmentInfo{},
	}
}

func (e *EnvironmentDetector) Detect() *EnvironmentInfo {
	e.mu.Lock()
	defer e.mu.Unlock()

	info := &EnvironmentInfo{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: e.getHostname(),
	}

	info.IsVM = e.detectVM()
	info.IsSandbox = e.detectSandbox()
	info.IsDebugged = e.detectDebugger()
	info.IsContainer = e.detectContainer()
	info.CPUCores = runtime.NumCPU()

	if info.IsVM {
		info.VMType = e.getVMType()
	}

	if info.IsSandbox {
		info.SandboxType = e.getSandboxType()
	}

	e.环境信息 = info
	e.detected = true

	return info
}

func (e *EnvironmentDetector) getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func (e *EnvironmentDetector) detectVM() bool {
	if runtime.GOOS == "windows" {
		return e.detectVMWindows()
	}
	return e.detectVMLinux()
}

func (e *EnvironmentDetector) detectVMWindows() bool {
	vmIndicators := []string{
		"SOFTWARE\\VMware, Inc.\\VMware Tools",
		"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
		"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
	}

	for _, key := range vmIndicators {
		if _, err := os.Stat(key); err == nil {
			return true
		}
	}

	return false
}

func (e *EnvironmentDetector) detectVMLinux() bool {
	vmFiles := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
	}

	for _, file := range vmFiles {
		if data, err := os.ReadFile(file); err == nil {
			content := string(data)
			if contains(content, "VMware") || contains(content, "VirtualBox") || contains(content, "QEMU") {
				return true
			}
		}
	}

	return false
}

func (e *EnvironmentDetector) getVMType() string {
	if runtime.GOOS == "windows" {
		return "VMware/VirtualBox"
	}
	return "KVM/QEMU"
}

func (e *EnvironmentDetector) detectSandbox() bool {
	if runtime.GOOS == "windows" {
		return e.detectSandboxWindows()
	}
	return e.detectSandboxLinux()
}

func (e *EnvironmentDetector) detectSandboxWindows() bool {
	sandboxIndicators := []string{
		"C:\\Program Files\\VMware\\VMware Tools",
		"C:\\Program Files\\Oracle\\VirtualBox Guest Additions",
	}

	for _, path := range sandboxIndicators {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}

func (e *EnvironmentDetector) detectSandboxLinux() bool {
	sandboxFiles := []string{
		"/etc/resolv.conf",
		"/proc/1/cgroup",
	}

	for _, file := range sandboxFiles {
		if data, err := os.ReadFile(file); err == nil {
			content := string(data)
			if contains(content, "sandbox") || contains(content, "docker") || contains(content, "lxc") {
				return true
			}
		}
	}

	return false
}

func (e *EnvironmentDetector) getSandboxType() string {
	return "generic"
}

func (e *EnvironmentDetector) detectDebugger() bool {
	return false
}

func (e *EnvironmentDetector) detectContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if contains(content, "docker") || contains(content, "lxc") || contains(content, "kubepods") {
			return true
		}
	}

	return false
}

func (e *EnvironmentDetector) GetInfo() *EnvironmentInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.环境信息
}

func (e *EnvironmentDetector) IsDetected() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.detected
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
