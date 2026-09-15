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

type UDPListener struct {
	mu          sync.RWMutex
	addr        string
	port        int
	running     bool
	connections map[string]*UDPConn
	packets     []PacketLog
}

type UDPConn struct {
	ID        string
	RemoteAddr string
	StartTime time.Time
	LastSeen  time.Time
	Packets   int64
}

type PacketLog struct {
	Timestamp time.Time
	RemoteAddr string
	Size      int
	Direction string
}

type UDPListenerConfig struct {
	Addr string
	Port int
}

func NewUDPListener(config UDPListenerConfig) *UDPListener {
	return &UDPListener{
		addr:        config.Addr,
		port:        config.Port,
		connections: make(map[string]*UDPConn),
		packets:     make([]PacketLog, 0),
	}
}

func (l *UDPListener) Start() error {
	l.mu.Lock()
	l.running = true
	l.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", l.addr, l.port)
	ln, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %v", err)
	}
	defer ln.Close()

	log.Printf("Starting UDP listener on %s", addr)

	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := ln.ReadFrom(buf)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}

		go l.handlePacket(buf[:n], remoteAddr)
	}
}

func (l *UDPListener) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.running = false
}

func (l *UDPListener) handlePacket(packet []byte, remoteAddr net.Addr) {
	connID := l.getOrCreateConn(remoteAddr.String())

	l.mu.Lock()
	conn := l.connections[connID]
	conn.Packets++
	conn.LastSeen = time.Now()

	l.packets = append(l.packets, PacketLog{
		Timestamp:  time.Now(),
		RemoteAddr: remoteAddr.String(),
		Size:       len(packet),
		Direction:  "in",
	})
	l.mu.Unlock()

	log.Printf("UDP packet from %s (%d bytes)", remoteAddr, len(packet))
}

func (l *UDPListener) getOrCreateConn(remoteAddr string) string {
	l.mu.RLock()
	for id, conn := range l.connections {
		if conn.RemoteAddr == remoteAddr {
			l.mu.RUnlock()
			return id
		}
	}
	l.mu.RUnlock()

	connID := generateUDPID()
	conn := &UDPConn{
		ID:         connID,
		RemoteAddr: remoteAddr,
		StartTime:  time.Now(),
		LastSeen:   time.Now(),
	}

	l.mu.Lock()
	l.connections[connID] = conn
	l.mu.Unlock()

	return connID
}

func (l *UDPListener) Send(remoteAddr string, data []byte) error {
	addr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to dial: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		return err
	}

	l.mu.Lock()
	l.packets = append(l.packets, PacketLog{
		Timestamp:  time.Now(),
		RemoteAddr: remoteAddr,
		Size:       len(data),
		Direction:  "out",
	})
	l.mu.Unlock()

	return nil
}

func (l *UDPListener) GetConnections() []*UDPConn {
	l.mu.RLock()
	defer l.mu.RUnlock()

	conns := make([]*UDPConn, 0, len(l.connections))
	for _, conn := range l.connections {
		conns = append(conns, conn)
	}
	return conns
}

func (l *UDPListener) GetPackets() []PacketLog {
	l.mu.RLock()
	defer l.mu.RUnlock()

	packets := make([]PacketLog, len(l.packets))
	copy(packets, l.packets)
	return packets
}

func (l *UDPListener) IsRunning() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.running
}

func generateUDPID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
