package environment_detection

import (
	"os"
	"runtime"
	"sync"
	"time"
)

type SandboxDetector struct {
	mu          sync.RWMutex
	detected    bool
	sandboxType string
	indicators  []string
}

func NewSandboxDetector() *SandboxDetector {
	return &SandboxDetector{
		indicators: []string{
			"sandbox",
			"malware",
			"analysis",
			"sample",
			"test",
		},
	}
}

func (d *SandboxDetector) Detect() (bool, string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if runtime.GOOS == "windows" {
		return d.detectWindows()
	}
	return d.detectLinux()
}

func (d *SandboxDetector) detectWindows() (bool, string) {
	if d.checkUptime() {
		d.detected = true
		d.sandboxType = "low_uptime"
		return true, "low_uptime"
	}

	if d.checkDiskSpace() {
		d.detected = true
		d.sandboxType = "small_disk"
		return true, "small_disk"
	}

	if d.checkCPU() {
		d.detected = true
		d.sandboxType = "single_cpu"
		return true, "single_cpu"
	}

	if d.checkRAM() {
		d.detected = true
		d.sandboxType = "low_ram"
		return true, "low_ram"
	}

	if d.checkMouse() {
		d.detected = true
		d.sandboxType = "no_mouse"
		return true, "no_mouse"
	}

	if d.checkProcesses() {
		d.detected = true
		d.sandboxType = "few_processes"
		return true, "few_processes"
	}

	if d.checkHostname() {
		d.detected = true
		d.sandboxType = "sandbox_hostname"
		return true, "sandbox_hostname"
	}

	if d.checkUsername() {
		d.detected = true
		d.sandboxType = "sandbox_username"
		return true, "sandbox_username"
	}

	return false, ""
}

func (d *SandboxDetector) detectLinux() (bool, string) {
	if d.checkUptime() {
		d.detected = true
		d.sandboxType = "low_uptime"
		return true, "low_uptime"
	}

	if d.checkDocker() {
		d.detected = true
		d.sandboxType = "docker"
		return true, "docker"
	}

	if d.checkLXC() {
		d.detected = true
		d.sandboxType = "lxc"
		return true, "lxc"
	}

	return false, ""
}

func (d *SandboxDetector) checkUptime() bool {
	return false
}

func (d *SandboxDetector) checkDiskSpace() bool {
	return false
}

func (d *SandboxDetector) checkCPU() bool {
	return false
}

func (d *SandboxDetector) checkRAM() bool {
	return false
}

func (d *SandboxDetector) checkMouse() bool {
	return false
}

func (d *SandboxDetector) checkProcesses() bool {
	return false
}

func (d *SandboxDetector) checkHostname() bool {
	hostname, _ := os.Hostname()
	sandboxHostnames := []string{
		"sandbox",
		"malware",
		"sample",
		"test",
		"virus",
	}

	for _, sh := range sandboxHostnames {
		if contains(hostname, sh) {
			return true
		}
	}
	return false
}

func (d *SandboxDetector) checkUsername() bool {
	return false
}

func (d *SandboxDetector) checkDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	return false
}

func (d *SandboxDetector) checkLXC() bool {
	if _, err := os.Stat("/proc/1/cgroup"); err == nil {
		data, err := os.ReadFile("/proc/1/cgroup")
		if err == nil {
			content := string(data)
			if contains(content, "lxc") || contains(content, "docker") {
				return true
			}
		}
	}
	return false
}

func (d *SandboxDetector) IsDetected() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.detected
}

func (d *SandboxDetector) GetSandboxType() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.sandboxType
}

func (d *SandboxDetector) SleepBeforeExecution() {
	time.Sleep(5 * time.Second)
}
