package listener

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type WebSocketListener struct {
	mu          sync.RWMutex
	addr        string
	port        int
	running     bool
	agents      map[string]*Agent
	tasks       map[string]*Task
	connections map[string]*websocket.Conn
}

func NewWebSocketListener(addr string, port int) *WebSocketListener {
	return &WebSocketListener{
		addr:        addr,
		port:        port,
		agents:      make(map[string]*Agent),
		tasks:       make(map[string]*Task),
		connections: make(map[string]*websocket.Conn),
	}
}

func (l *WebSocketListener) Start() error {
	l.mu.Lock()
	l.running = true
	l.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", l.handleWebSocket)
	mux.HandleFunc("/api/v1/health", l.handleHealth)

	addr := fmt.Sprintf("%s:%d", l.addr, l.port)
	log.Printf("Starting WebSocket listener on %s", addr)

	return http.ListenAndServe(addr, mux)
}

func (l *WebSocketListener) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.running = false

	for id, conn := range l.connections {
		conn.Close()
		delete(l.connections, id)
	}
}

func (l *WebSocketListener) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	connID := generateWSID()
	l.mu.Lock()
	l.connections[connID] = conn
	l.mu.Unlock()

	defer func() {
		l.mu.Lock()
		delete(l.connections, connID)
		l.mu.Unlock()
		conn.Close()
	}()

	log.Printf("New WebSocket connection: %s", connID)

	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}

		l.handleMessage(connID, messageType, message)
	}
}

func (l *WebSocketListener) handleMessage(connID string, messageType int, message []byte) {
	log.Printf("Received message from %s: %s", connID, string(message))
}

func (l *WebSocketListener) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "ok"}`)
}

func (l *WebSocketListener) SendMessage(connID string, message []byte) error {
	l.mu.RLock()
	conn, exists := l.connections[connID]
	l.mu.RUnlock()

	if !exists {
		return fmt.Errorf("connection not found: %s", connID)
	}

	return conn.WriteMessage(websocket.TextMessage, message)
}

func (l *WebSocketListener) Broadcast(message []byte) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for _, conn := range l.connections {
		conn.WriteMessage(websocket.TextMessage, message)
	}
}

func (l *WebSocketListener) AddTask(task *Task) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tasks[task.ID] = task
}

func (l *WebSocketListener) GetConnections() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	ids := make([]string, 0, len(l.connections))
	for id := range l.connections {
		ids = append(ids, id)
	}
	return ids
}

func generateWSID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
