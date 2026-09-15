package environment_detection

import (
	"os"
	"runtime"
	"sync"
)

type EDRDetector struct {
	mu          sync.RWMutex
	edrNames    []string
	detected    bool
	edrType     string
}

func NewEDRDetector() *EDRDetector {
	return &EDRDetector{
		edrNames: []string{
			"CrowdStrike",
			"SentinelOne",
			"Carbon Black",
			"Defender",
			"Cylance",
			"Symantec",
			"McAfee",
			"Tanium",
			"Deep Instinct",
			"Comodo",
		},
	}
}

func (d *EDRDetector) Detect() (bool, string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if runtime.GOOS == "windows" {
		return d.detectWindows()
	}
	return d.detectLinux()
}

func (d *EDRDetector) detectWindows() (bool, string) {
	processes := []string{
		"csfalconservice.exe",
		"sentinelagent.exe",
		"cb.exe",
		"msmpeng.exe",
		"cylancesvc.exe",
		"symcorpui.exe",
		"mcshield.exe",
		"taniumclient.exe",
	}

	for _, proc := range processes {
		if d.isProcessRunning(proc) {
			d.detected = true
			d.edrType = proc
			return true, proc
		}
	}

	services := []string{
		"CrowdStrike",
		"SentinelOne",
		"CarbonBlack",
		"WinDefend",
		"Cylance",
	}

	for _, svc := range services {
		if d.isServiceRunning(svc) {
			d.detected = true
			d.edrType = svc
			return true, svc
		}
	}

	return false, ""
}

func (d *EDRDetector) detectLinux() (bool, string) {
	processes := []string{
		"cs-falcon-sensor",
		"sentinelone",
		"cb-daemon",
		"clamav",
		"ds_agent",
	}

	for _, proc := range processes {
		if d.isProcessRunning(proc) {
			d.detected = true
			d.edrType = proc
			return true, proc
		}
	}

	return false, ""
}

func (d *EDRDetector) isProcessRunning(name string) bool {
	return false
}

func (d *EDRDetector) isServiceRunning(name string) bool {
	return false
}

func (d *EDRDetector) IsDetected() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.detected
}

func (d *EDRDetector) GetEDRType() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.edrType
}

func (d *EDRDetector) DetectHooks() bool {
	if runtime.GOOS == "windows" {
		return d.detectWindowsHooks()
	}
	return false
}

func (d *EDRDetector) detectWindowsHooks() bool {
	hookIndicators := []string{
		"ntdll.dll",
		"kernel32.dll",
		"advapi32.dll",
	}

	for _, dll := range hookIndicators {
		if d.checkDLLHook(dll) {
			return true
		}
	}

	return false
}

func (d *EDRDetector) checkDLLHook(dll string) bool {
	return false
}

func (d *EDRDetector) GetHookedFunctions() []string {
	return []string{}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
