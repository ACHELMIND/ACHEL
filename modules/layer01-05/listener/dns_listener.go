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
	mu          sync.RWMutex
	addr        string
	port        int
	running     bool
	agents      map[string]*DNSAgent
	tasks       map[string]*DNSTask
	connections map[string]*DNSConn
}

type DNSAgent struct {
	ID        string
	Hostname  string
	IP        string
	LastSeen  time.Time
	Connected bool
}

type DNSTask struct {
	ID        string
	AgentID   string
	Payload   string
	Status    string
	CreatedAt time.Time
}

type DNSConn struct {
	ID        string
	RemoteAddr string
	Protocol  string
	StartTime time.Time
}

type DNSListenerConfig struct {
	Addr string
	Port int
}

func NewDNSListener(config DNSListenerConfig) *DNSListener {
	return &DNSListener{
		addr:        config.Addr,
		port:        config.Port,
		agents:      make(map[string]*DNSAgent),
		tasks:       make(map[string]*DNSTask),
		connections: make(map[string]*DNSConn),
	}
}

func (l *DNSListener) Start() error {
	l.mu.Lock()
	l.running = true
	l.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", l.addr, l.port)
	ln, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start DNS listener: %v", err)
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
	connID := generateDNSID()

	conn := &DNSConn{
		ID:         connID,
		RemoteAddr: remoteAddr.String(),
		Protocol:   "DNS",
		StartTime:  time.Now(),
	}

	l.mu.Lock()
	l.connections[connID] = conn
	l.mu.Unlock()

	log.Printf("DNS packet from %s (%d bytes)", remoteAddr, len(packet))
}

func (l *DNSListener) RegisterAgent(agentID, hostname, ip string) {
	agent := &DNSAgent{
		ID:        agentID,
		Hostname:  hostname,
		IP:        ip,
		LastSeen:  time.Now(),
		Connected: true,
	}

	l.mu.Lock()
	l.agents[agentID] = agent
	l.mu.Unlock()
}

func (l *DNSListener) GetAgents() []*DNSAgent {
	l.mu.RLock()
	defer l.mu.RUnlock()

	agents := make([]*DNSAgent, 0, len(l.agents))
	for _, agent := range l.agents {
		agents = append(agents, agent)
	}
	return agents
}

func (l *DNSListener) GetConnections() []*DNSConn {
	l.mu.RLock()
	defer l.mu.RUnlock()

	conns := make([]*DNSConn, 0, len(l.connections))
	for _, conn := range l.connections {
		conns = append(conns, conn)
	}
	return conns
}

func (l *DNSListener) IsRunning() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.running
}

func generateDNSID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
