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

type TCPListener struct {
	mu          sync.RWMutex
	addr        string
	port        int
	running     bool
	connections map[string]*TCPConn
	agents      map[string]*TCPAgent
}

type TCPConn struct {
	ID        string
	Conn      net.Conn
	RemoteAddr string
	StartTime time.Time
	BytesIn   int64
	BytesOut  int64
}

type TCPAgent struct {
	ID        string
	ConnID    string
	Hostname  string
	IP        string
	LastSeen  time.Time
	Connected bool
}

type TCPListenerConfig struct {
	Addr string
	Port int
}

func NewTCPListener(config TCPListenerConfig) *TCPListener {
	return &TCPListener{
		addr:        config.Addr,
		port:        config.Port,
		connections: make(map[string]*TCPConn),
		agents:      make(map[string]*TCPAgent),
	}
}

func (l *TCPListener) Start() error {
	l.mu.Lock()
	l.running = true
	l.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", l.addr, l.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start TCP listener: %v", err)
	}
	defer ln.Close()

	log.Printf("Starting TCP listener on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("TCP accept error: %v", err)
			continue
		}

		go l.handleConnection(conn)
	}
}

func (l *TCPListener) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.running = false

	for id, conn := range l.connections {
		conn.Conn.Close()
		delete(l.connections, id)
	}
}

func (l *TCPListener) handleConnection(conn net.Conn) {
	connID := generateTCPID()

	tcpConn := &TCPConn{
		ID:         connID,
		Conn:       conn,
		RemoteAddr: conn.RemoteAddr().String(),
		StartTime:  time.Now(),
	}

	l.mu.Lock()
	l.connections[connID] = tcpConn
	l.mu.Unlock()

	defer func() {
		l.mu.Lock()
		delete(l.connections, connID)
		l.mu.Unlock()
		conn.Close()
	}()

	log.Printf("New TCP connection: %s from %s", connID, conn.RemoteAddr())

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("TCP read error from %s: %v", connID, err)
			break
		}

		l.mu.Lock()
		tcpConn.BytesIn += int64(n)
		l.mu.Unlock()

		log.Printf("Received %d bytes from %s", n, connID)
	}
}

func (l *TCPListener) Send(connID string, data []byte) error {
	l.mu.RLock()
	conn, exists := l.connections[connID]
	l.mu.RUnlock()

	if !exists {
		return fmt.Errorf("connection not found: %s", connID)
	}

	n, err := conn.Conn.Write(data)
	if err != nil {
		return err
	}

	l.mu.Lock()
	conn.BytesOut += int64(n)
	l.mu.Unlock()

	return nil
}

func (l *TCPListener) GetConnections() []*TCPConn {
	l.mu.RLock()
	defer l.mu.RUnlock()

	conns := make([]*TCPConn, 0, len(l.connections))
	for _, conn := range l.connections {
		conns = append(conns, conn)
	}
	return conns
}

func (l *TCPListener) GetConnection(connID string) *TCPConn {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.connections[connID]
}

func (l *TCPListener) IsRunning() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.running
}

func generateTCPID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
