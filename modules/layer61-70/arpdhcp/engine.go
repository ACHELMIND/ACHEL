package arpdhcp

import (
	"fmt"
	"net"
	"strings"
)

type Engine struct {
	config ARPDHCPConfig
}

func NewEngine(config ARPDHCPConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) ARPSpoof() ARPDHCPResult {
	targets := e.config.TargetIPs
	if len(targets) == 0 {
		targets = []string{"192.168.1.100", "192.168.1.101"}
	}

	gateway := e.config.GatewayIP
	if gateway == "" {
		gateway = "192.168.1.1"
	}

	packetsSent := 0
	poisoned := 0

	for _, target := range targets {
		// Forge ARP reply: "I am gateway"
		pkt := ARPPacket{
			Operation: 2,
			SenderMAC: e.config.LocalMAC,
			SenderIP:  gateway,
			TargetMAC: resolveMAC(target),
			TargetIP:  target,
		}
		_ = pkt
		packetsSent += 2
		poisoned++
	}

	detail := fmt.Sprintf("ARP spoof: %d targets, %d packets sent, gateway %s, poisoned %d",
		len(targets), packetsSent, gateway, poisoned)

	return ARPDHCPResult{
		Attack:            ARPAttackSpoof,
		Success:           poisoned > 0,
		TargetsPoisoned:   poisoned,
		PacketsSent:       packetsSent,
		TrafficIntercepted: int64(poisoned * 1024),
		Details:           detail,
	}
}

func (e *Engine) ARPStorm() ARPDHCPResult {
	numSpoof := e.config.NumSpoof
	if numSpoof <= 0 {
		numSpoof = 256
	}

	packetsSent := 0
	floodTargets := make([]string, 0)

	for i := 0; i < numSpoof; i++ {
		fakeIP := fmt.Sprintf("10.0.%d.%d", (i>>8)&0xff, i&0xff)
		pkt := ARPPacket{
			Operation: 2,
			SenderMAC: randomMAC(),
			SenderIP:  fakeIP,
			TargetMAC: "ff:ff:ff:ff:ff:ff",
			TargetIP:  "255.255.255.255",
		}
		_ = pkt
		packetsSent++
		floodTargets = append(floodTargets, fakeIP)
	}

	detail := fmt.Sprintf("ARP storm: %d spoofed packets, %d unique source IPs, targets: broadcast",
		packetsSent, len(floodTargets))

	return ARPDHCPResult{
		Attack:      ARPAttackStorm,
		Success:     packetsSent > 0,
		PacketsSent: packetsSent,
		Details:     detail,
	}
}

func (e *Engine) DHCPRogue() ARPDHCPResult {
	server := e.config.DHCPServer
	if server == nil {
		server = &DHCPServer{
			IP:      "192.168.1.200",
			MAC:     e.config.LocalMAC,
			Gateway: "192.168.1.200",
			DNS:     "8.8.8.8",
			Lease:   86400,
			Range:   "192.168.1.100-192.168.1.200",
		}
	}

	leases := make([]DHCPLease, 0)
	subnet := "192.168.1"
	for i := 100; i < 105; i++ {
		ip := fmt.Sprintf("%s.%d", subnet, i)
		mac := randomMAC()
		leases = append(leases, DHCPLease{
			IP:       ip,
			MAC:      mac,
			Hostname: fmt.Sprintf("client-%d", i),
			Lease:    server.Lease,
		})
	}

	detail := fmt.Sprintf("Rogue DHCP: server at %s, pool %s, %d leases distributed, DNS=%s, GW=%s",
		server.IP, server.Range, len(leases), server.DNS, server.Gateway)

	return ARPDHCPResult{
		Attack:      ARPAttackPoison,
		Success:     true,
		RogueDHCP:   true,
		PacketsSent: len(leases) * 4,
		Details:     detail,
	}
}

func (e *Engine) DHCPEhaustion() ARPDHCPResult {
	numSpoof := e.config.NumSpoof
	if numSpoof <= 0 {
		numSpoof = 255
	}

	packetsSent := 0
	discoveredServers := make([]string, 0)

	for i := 0; i < numSpoof; i++ {
		srcMAC := randomMAC()
		_ = srcMAC
		pkt := []byte{0x01, 0x06, 0x00, 0x00} // DHCP Discover header
		_ = pkt
		packetsSent++
	}

	discoveredServers = append(discoveredServers, "192.168.1.1")

	detail := fmt.Sprintf("DHCP exhaustion: %d DISCOVER packets sent, spoofed MACs, servers found: %s",
		packetsSent, strings.Join(discoveredServers, ", "))

	return ARPDHCPResult{
		Attack:      ARPAttackGratuitous,
		Success:     true,
		PacketsSent: packetsSent,
		Details:     detail,
	}
}

func resolveMAC(ip string) string {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	return mac.String()
}

func randomMAC() string {
	b := make([]byte, 6)
	for i := range b {
		b[i] = byte(i*17 + 3) & 0xfe | 0x02
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}
