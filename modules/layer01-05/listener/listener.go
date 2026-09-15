package listener

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type GenericListener struct {
	mu        sync.RWMutex
	addr      string
	port      int
	running   bool
	connections map[string]net.Conn
}

func NewGenericListener(addr string, port int) *GenericListener {
	return &GenericListener{
		addr:        addr,
		port:        port,
		connections: make(map[string]net.Conn),
	}
}

func (l *GenericListener) Start() error {
	l.mu.Lock()
	l.running = true
	l.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", l.addr, l.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("Starting generic listener on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go l.handleConnection(conn)
	}
}

func (l *GenericListener) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.running = false

	for id, conn := range l.connections {
		conn.Close()
		delete(l.connections, id)
	}
}

func (l *GenericListener) handleConnection(conn net.Conn) {
	connID := fmt.Sprintf("%d", time.Now().UnixNano())

	l.mu.Lock()
	l.connections[connID] = conn
	l.mu.Unlock()

	defer func() {
		l.mu.Lock()
		delete(l.connections, connID)
		l.mu.Unlock()
		conn.Close()
	}()

	log.Printf("New connection: %s from %s", connID, conn.RemoteAddr())

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Read error from %s: %v", connID, err)
			break
		}

		log.Printf("Received %d bytes from %s", n, connID)
	}
}

func (l *GenericListener) Send(connID string, data []byte) error {
	l.mu.RLock()
	conn, exists := l.connections[connID]
	l.mu.RUnlock()

	if !exists {
		return fmt.Errorf("connection not found: %s", connID)
	}

	_, err := conn.Write(data)
	return err
}

func (l *GenericListener) GetConnections() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	ids := make([]string, 0, len(l.connections))
	for id := range l.connections {
		ids = append(ids, id)
	}
	return ids
}

func (l *GenericListener) IsRunning() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.running
}
