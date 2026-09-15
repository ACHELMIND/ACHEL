package environment_detection

import (
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
)

type NetworkMonitorDetector struct {
	mu       sync.RWMutex
	detected bool
	monitorType string
}

func NewNetworkMonitorDetector() *NetworkMonitorDetector {
	return &NetworkMonitorDetector{}
}

func (d *NetworkMonitorDetector) Detect() (bool, string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if runtime.GOOS == "windows" {
		return d.detectWindows()
	}
	return d.detectLinux()
}

func (d *NetworkMonitorDetector) detectWindows() (bool, string) {
	if d.checkFirewall() {
		d.detected = true
		d.monitorType = "firewall"
		return true, "firewall"
	}

	if d.checkProxy() {
		d.detected = true
		d.monitorType = "proxy"
		return true, "proxy"
	}

	if d.checkVPN() {
		d.detected = true
		d.monitorType = "vpn"
		return true, "vpn"
	}

	if d.checkSniffer() {
		d.detected = true
		d.monitorType = "sniffer"
		return true, "sniffer"
	}

	return false, ""
}

func (d *NetworkMonitorDetector) detectLinux() (bool, string) {
	if d.checkIptables() {
		d.detected = true
		d.monitorType = "iptables"
		return true, "iptables"
	}

	if d.checkNftables() {
		d.detected = true
		d.monitorType = "nftables"
		return true, "nftables"
	}

	if d.checkTcpdump() {
		d.detected = true
		d.monitorType = "tcpdump"
		return true, "tcpdump"
	}

	if d.checkSuricata() {
		d.detected = true
		d.monitorType = "suricata"
		return true, "suricata"
	}

	if d.checkSnort() {
		d.detected = true
		d.monitorType = "snort"
		return true, "snort"
	}

	return false, ""
}

func (d *NetworkMonitorDetector) checkFirewall() bool {
	return false
}

func (d *NetworkMonitorDetector) checkProxy() bool {
	proxyVars := []string{
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"ALL_PROXY",
		"http_proxy",
		"https_proxy",
		"all_proxy",
	}

	for _, v := range proxyVars {
		if val := os.Getenv(v); val != "" {
			return true
		}
	}
	return false
}

func (d *NetworkMonitorDetector) checkVPN() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range ifaces {
		if strings.Contains(iface.Name, "tun") ||
			strings.Contains(iface.Name, "tap") ||
			strings.Contains(iface.Name, "ppp") {
			return true
		}
	}
	return false
}

func (d *NetworkMonitorDetector) checkSniffer() bool {
	return false
}

func (d *NetworkMonitorDetector) checkIptables() bool {
	if _, err := os.Stat("/sbin/iptables"); err == nil {
		return true
	}
	return false
}

func (d *NetworkMonitorDetector) checkNftables() bool {
	if _, err := os.Stat("/sbin/nft"); err == nil {
		return true
	}
	return false
}

func (d *NetworkMonitorDetector) checkTcpdump() bool {
	if _, err := os.Stat("/usr/sbin/tcpdump"); err == nil {
		return true
	}
	return false
}

func (d *NetworkMonitorDetector) checkSuricata() bool {
	if _, err := os.Stat("/usr/bin/suricata"); err == nil {
		return true
	}
	return false
}

func (d *NetworkMonitorDetector) checkSnort() bool {
	if _, err := os.Stat("/usr/bin/snort"); err == nil {
		return true
	}
	return false
}

func (d *NetworkMonitorDetector) IsDetected() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.detected
}

func (d *NetworkMonitorDetector) GetMonitorType() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.monitorType
}

func (d *NetworkMonitorDetector) GetNetworkInterfaces() []net.Interface {
	ifaces, _ := net.Interfaces()
	return ifaces
}

func (d *NetworkMonitorDetector) GetDNS() []string {
	return nil
}

func (d *NetworkMonitorDetector) GetRoutingTable() []string {
	return nil
}
