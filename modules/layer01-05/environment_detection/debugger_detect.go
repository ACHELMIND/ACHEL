package environment_detection

import (
	"os"
	"runtime"
	"sync"
	"time"
)

type DebuggerDetector struct {
	mu       sync.RWMutex
	detected bool
	debuggerType string
}

func NewDebuggerDetector() *DebuggerDetector {
	return &DebuggerDetector{}
}

func (d *DebuggerDetector) Detect() (bool, string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if runtime.GOOS == "windows" {
		return d.detectWindows()
	}
	return d.detectLinux()
}

func (d *DebuggerDetector) detectWindows() (bool, string) {
	if d.checkIsDebuggerPresent() {
		d.detected = true
		d.debuggerType = "IsDebuggerPresent"
		return true, "IsDebuggerPresent"
	}

	if d.checkCheckRemoteDebugger() {
		d.detected = true
		d.debuggerType = "CheckRemoteDebuggerPresent"
		return true, "CheckRemoteDebuggerPresent"
	}

	if d.checkNtGlobalFlag() {
		d.detected = true
		d.debuggerType = "NtGlobalFlag"
		return true, "NtGlobalFlag"
	}

	if d.checkHeapFlags() {
		d.detected = true
		d.debuggerType = "HeapFlags"
		return true, "HeapFlags"
	}

	if d.checkHardwareBreakpoints() {
		d.detected = true
		d.debuggerType = "HardwareBreakpoints"
		return true, "HardwareBreakpoints"
	}

	if d.checkTiming() {
		d.detected = true
		d.debuggerType = "Timing"
		return true, "Timing"
	}

	if d.checkInt3() {
		d.detected = true
		d.debuggerType = "Int3"
		return true, "Int3"
	}

	if d.checkICE() {
		d.detected = true
		d.debuggerType = "ICE"
		return true, "ICE"
	}

	if d.checkCPUID() {
		d.detected = true
		d.debuggerType = "CPUID"
		return true, "CPUID"
	}

	return false, ""
}

func (d *DebuggerDetector) detectLinux() (bool, string) {
	if d.checkTracerPid() {
		d.detected = true
		d.debuggerType = "TracerPid"
		return true, "TracerPid"
	}

	if d.checkStatusFile() {
		d.detected = true
		d.debuggerType = "StatusFile"
		return true, "StatusFile"
	}

	if d.checkProcSelf() {
		d.detected = true
		d.debuggerType = "ProcSelf"
		return true, "ProcSelf"
	}

	return false, ""
}

func (d *DebuggerDetector) checkIsDebuggerPresent() bool {
	return false
}

func (d *DebuggerDetector) checkCheckRemoteDebugger() bool {
	return false
}

func (d *DebuggerDetector) checkNtGlobalFlag() bool {
	return false
}

func (d *DebuggerDetector) checkHeapFlags() bool {
	return false
}

func (d *DebuggerDetector) checkHardwareBreakpoints() bool {
	return false
}

func (d *DebuggerDetector) checkTiming() bool {
	start := time.Now()
	time.Sleep(100 * time.Millisecond)
	elapsed := time.Since(start)
	return elapsed > 200*time.Millisecond
}

func (d *DebuggerDetector) checkInt3() bool {
	return false
}

func (d *DebuggerDetector) checkICE() bool {
	return false
}

func (d *DebuggerDetector) checkCPUID() bool {
	return false
}

func (d *DebuggerDetector) checkTracerPid() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}

	content := string(data)
	return contains(content, "TracerPid:\t0")
}

func (d *DebuggerDetector) checkStatusFile() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}

	content := string(data)
	return contains(content, "TracerPid:") && !contains(content, "TracerPid:\t0")
}

func (d *DebuggerDetector) checkProcSelf() bool {
	if _, err := os.Stat("/proc/self/exe"); err != nil {
		return true
	}
	return false
}

func (d *DebuggerDetector) IsDetected() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.detected
}

func (d *DebuggerDetector) GetDebuggerType() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.debuggerType
}

func (d *DebuggerDetector) AntiDebug() {
	for {
		if detected, _ := d.Detect(); detected {
			os.Exit(1)
		}
		time.Sleep(5 * time.Second)
	}
}
