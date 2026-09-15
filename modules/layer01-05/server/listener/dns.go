package listener

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type DNSListener struct {
	mu        sync.RWMutex
	addr      string
	port      int
	running   bool
	agents    map[string]*Agent
	tasks     map[string]*Task
	results   []*Result
	domain    string
}

func NewDNSListener(addr string, port int, domain string) *DNSListener {
	return &DNSListener{
		addr:   addr,
		port:   port,
		domain: domain,
		agents: make(map[string]*Agent),
		tasks:  make(map[string]*Task),
	}
}

func (l *DNSListener) Start() error {
	l.mu.Lock()
	l.running = true
	l.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", l.addr, l.port)
	ln, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start DNS listener: %w", err)
	}
	defer ln.Close()

	log.Printf("Starting DNS listener on %s", addr)

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := ln.ReadFrom(buf)
		if err != nil {
			log.Printf("DNS read error: %v", err)
			continue
		}

		go l.handleDNSPacket(buf[:n], remoteAddr)
	}
}

func (l *DNSListener) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.running = false
}

func (l *DNSListener) handleDNSPacket(packet []byte, remoteAddr net.Addr) {
	if len(packet) < 12 {
		return
	}

	qdcount := int(packet[4])<<8 | int(packet[5])
	offset := 12

	for i := 0; i < qdcount; i++ {
		name, offset := l.parseDNSName(packet, offset)
		if offset+4 > len(packet) {
			break
		}

		qtype := uint16(packet[offset])<<8 | uint16(packet[offset+1])
		offset += 4

		log.Printf("DNS query: %s (type: %d) from %s", name, qtype, remoteAddr)

		l.processDNSQuery(name, qtype, remoteAddr)
	}
}

func (l *DNSListener) parseDNSName(packet []byte, offset int) (string, int) {
	var name []byte
	for {
		if offset >= len(packet) {
			break
		}
		length := int(packet[offset])
		offset++
		if length == 0 {
			break
		}
		if offset+length > len(packet) {
			break
		}
		name = append(name, packet[offset:offset+length]...)
		name = append(name, '.')
		offset += length
	}
	if len(name) > 0 {
		name = name[:len(name)-1]
	}
	return string(name), offset
}

func (l *DNSListener) processDNSQuery(name string, qtype uint16, remoteAddr net.Addr) {
	agentID := l.extractAgentFromSubdomain(name)
	if agentID != "" {
		l.mu.Lock()
		if agent, exists := l.agents[agentID]; exists {
			agent.LastSeen = time.Now()
		}
		l.mu.Unlock()
	}
}

func (l *DNSListener) extractAgentFromSubdomain(name string) string {
	return ""
}

func (l *DNSListener) AddTask(task *Task) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tasks[task.ID] = task
}

func (l *DNSListener) GetAgents() []*Agent {
	l.mu.RLock()
	defer l.mu.RUnlock()

	agents := make([]*Agent, 0, len(l.agents))
	for _, agent := range l.agents {
		agents = append(agents, agent)
	}
	return agents
}

func generateDNSID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
