package environment_detection

import (
	"os"
	"runtime"
	"strings"
	"sync"
)

type VMDetector struct {
	mu       sync.RWMutex
	detected bool
	vmType   string
}

func NewVMDetector() *VMDetector {
	return &VMDetector{}
}

func (d *VMDetector) Detect() (bool, string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if runtime.GOOS == "windows" {
		return d.detectWindows()
	}
	return d.detectLinux()
}

func (d *VMDetector) detectWindows() (bool, string) {
	if d.checkRegistry() {
		d.detected = true
		d.vmType = "registry"
		return true, "registry"
	}

	if d.checkDevices() {
		d.detected = true
		d.vmType = "devices"
		return true, "devices"
	}

	if d.checkProcesses() {
		d.detected = true
		d.vmType = "processes"
		return true, "processes"
	}

	if d.checkMAC() {
		d.detected = true
		d.vmType = "mac_address"
		return true, "mac_address"
	}

	if d.checkCPUID() {
		d.detected = true
		d.vmType = "cpuid"
		return true, "cpuid"
	}

	return false, ""
}

func (d *VMDetector) detectLinux() (bool, string) {
	if d.checkSysVendor() {
		d.detected = true
		d.vmType = "sys_vendor"
		return true, "sys_vendor"
	}

	if d.checkProductName() {
		d.detected = true
		d.vmType = "product_name"
		return true, "product_name"
	}

	if d.checkDMI() {
		d.detected = true
		d.vmType = "dmi"
		return true, "dmi"
	}

	if d.checkModules() {
		d.detected = true
		d.vmType = "modules"
		return true, "modules"
	}

	return false, ""
}

func (d *VMDetector) checkRegistry() bool {
	vmKeys := []string{
		`SOFTWARE\VMware, Inc.\VMware Tools`,
		`SOFTWARE\Oracle\VirtualBox Guest Additions`,
		`SYSTEM\CurrentControlSet\Services\VBoxGuest`,
		`SYSTEM\CurrentControlSet\Services\vmci`,
		`SYSTEM\CurrentControlSet\Services\vmhgfs`,
	}

	for _, key := range vmKeys {
		if _, err := os.Stat(key); err == nil {
			return true
		}
	}
	return false
}

func (d *VMDetector) checkDevices() bool {
	vmDevices := []string{
		`\\.\VBoxMiniRdrDN`,
		`\\.\VBoxGuest`,
		`\\.\VBoxTrayIPC`,
		`\\.\pipe\VBoxTrayIPC`,
		`\\.\HGFS`,
	}

	for _, device := range vmDevices {
		if _, err := os.Stat(device); err == nil {
			return true
		}
	}
	return false
}

func (d *VMDetector) checkProcesses() bool {
	vmProcesses := []string{
		"vmtoolsd.exe",
		"vmwaretray.exe",
		"vmwareuser.exe",
		"vgauthservice.exe",
		"vmacthlp.exe",
		"VBoxService.exe",
		"VBoxTray.exe",
	}

	for _, proc := range vmProcesses {
		if d.isProcessRunning(proc) {
			return true
		}
	}
	return false
}

func (d *VMDetector) checkMAC() bool {
	return false
}

func (d *VMDetector) checkCPUID() bool {
	return false
}

func (d *VMDetector) checkSysVendor() bool {
	data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if err != nil {
		return false
	}
	content := strings.ToLower(string(data))
	return strings.Contains(content, "vmware") ||
		strings.Contains(content, "virtualbox") ||
		strings.Contains(content, "qemu") ||
		strings.Contains(content, "xen")
}

func (d *VMDetector) checkProductName() bool {
	data, err := os.ReadFile("/sys/class/dmi/id/product_name")
	if err != nil {
		return false
	}
	content := strings.ToLower(string(data))
	return strings.Contains(content, "vmware") ||
		strings.Contains(content, "virtualbox") ||
		strings.Contains(content, "qemu") ||
		strings.Contains(content, "virtual")
}

func (d *VMDetector) checkDMI() bool {
	data, err := os.ReadFile("/sys/class/dmi/id/board_vendor")
	if err != nil {
		return false
	}
	content := strings.ToLower(string(data))
	return strings.Contains(content, "vmware") ||
		strings.Contains(content, "oracle") ||
		strings.Contains(content, "qemu")
}

func (d *VMDetector) checkModules() bool {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}
	content := strings.ToLower(string(data))
	return strings.Contains(content, "vmw_") ||
		strings.Contains(content, "vbox") ||
		strings.Contains(content, "virtio")
}

func (d *VMDetector) isProcessRunning(name string) bool {
	return false
}

func (d *VMDetector) IsDetected() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.detected
}

func (d *VMDetector) GetVMType() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.vmType
}

func (d *VMDetector) GetVMName() string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	switch d.vmType {
	case "registry", "devices", "processes", "mac_address", "cpuid":
		if strings.Contains(d.vmType, "vmware") {
			return "VMware"
		}
		if strings.Contains(d.vmType, "virtualbox") {
			return "VirtualBox"
		}
	case "sys_vendor", "product_name", "dmi", "modules":
		return d.vmType
	}

	return "Unknown"
}
