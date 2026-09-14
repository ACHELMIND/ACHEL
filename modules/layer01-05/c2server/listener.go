package c2server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/eventbus"
	"github.com/angel-platform/angel/pkg/logger"
)

type Listener interface {
	Start() error
	Stop()
	Type() string
	Status() string
}

type HTTPListener struct {
	mu       sync.RWMutex
	status   string
	addr     string
	port     int
	server   *http.Server
	crypto   *ServerCrypto
	eb       *eventbus.EventBus
	log      *logger.Logger
	handlers map[string]http.HandlerFunc
}

func NewHTTPListener(addr string, port int, crypto *ServerCrypto, eb *eventbus.EventBus, log *logger.Logger) *HTTPListener {
	l := &HTTPListener{
		status:   "stopped",
		addr:     addr,
		port:     port,
		crypto:   crypto,
		eb:       eb,
		log:      log,
		handlers: make(map[string]http.HandlerFunc),
	}
	l.registerHandlers()
	return l
}

func (l *HTTPListener) registerHandlers() {
	l.handlers["/register"] = l.handleRegister
	l.handlers["/checkin"] = l.handleCheckIn
	l.handlers["/task"] = l.handleTask
	l.handlers["/result"] = l.handleResult
}

func (l *HTTPListener) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	decrypted, err := l.crypto.DecryptPayload(body)
	if err != nil {
		l.log.Error("decrypt registration: %v", err)
		http.Error(w, "decryption failed", http.StatusBadRequest)
		return
	}
	l.eb.Publish("agent.register", "http_listener", "registration", map[string]interface{}{
		"data": string(decrypted),
	})
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (l *HTTPListener) handleCheckIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	decrypted, err := l.crypto.DecryptPayload(body)
	if err != nil {
		l.log.Error("decrypt checkin: %v", err)
		http.Error(w, "decryption failed", http.StatusBadRequest)
		return
	}
	l.eb.Publish("agent.checkin", "http_listener", "checkin", map[string]interface{}{
		"data": string(decrypted),
	})
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (l *HTTPListener) handleTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agentID := r.URL.Query().Get("id")
	if agentID == "" {
		http.Error(w, "missing agent id", http.StatusBadRequest)
		return
	}
	l.eb.Publish("agent.task", "http_listener", "task_request", map[string]interface{}{
		"agent_id": agentID,
	})
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (l *HTTPListener) handleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	decrypted, err := l.crypto.DecryptPayload(body)
	if err != nil {
		l.log.Error("decrypt result: %v", err)
		http.Error(w, "decryption failed", http.StatusBadRequest)
		return
	}
	l.eb.Publish("agent.result", "http_listener", "result", map[string]interface{}{
		"data": string(decrypted),
	})
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (l *HTTPListener) Start() error {
	mux := http.NewServeMux()
	for path, handler := range l.handlers {
		mux.HandleFunc(path, handler)
	}
	addr := fmt.Sprintf("%s:%d", l.addr, l.port)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	l.server = &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}
	l.mu.Lock()
	l.status = "running"
	l.mu.Unlock()
	l.log.Info("HTTP listener starting on %s", addr)
	go func() {
		if err := l.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			l.log.Error("HTTP listener error: %v", err)
		}
	}()
	return nil
}

func (l *HTTPListener) Stop() {
	l.mu.Lock()
	l.status = "stopped"
	l.mu.Unlock()
	if l.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		l.server.Shutdown(ctx)
	}
}

func (l *HTTPListener) Type() string {
	return "http"
}

func (l *HTTPListener) Status() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.status
}

type DNSListener struct {
	mu     sync.RWMutex
	status string
	addr   string
	port   int
	conn   net.PacketConn
	crypto *ServerCrypto
	eb     *eventbus.EventBus
	log    *logger.Logger
	cancel context.CancelFunc
}

func NewDNSListener(addr string, port int, crypto *ServerCrypto, eb *eventbus.EventBus, log *logger.Logger) *DNSListener {
	return &DNSListener{
		status: "stopped",
		addr:   addr,
		port:   port,
		crypto: crypto,
		eb:     eb,
		log:    log,
	}
}

func (l *DNSListener) Start() error {
	addr := fmt.Sprintf("%s:%d", l.addr, l.port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	l.conn = conn
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	l.mu.Lock()
	l.status = "running"
	l.mu.Unlock()
	l.log.Info("DNS listener starting on %s", addr)
	go l.serve(ctx)
	return nil
}

func (l *DNSListener) serve(ctx context.Context) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			l.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, remoteAddr, err := l.conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			go l.handleDNSQuery(data, remoteAddr)
		}
	}
}

func (l *DNSListener) handleDNSQuery(data []byte, remoteAddr net.Addr) {
	decrypted, err := l.crypto.DecryptPayload(data)
	if err != nil {
		l.log.Error("decrypt DNS query: %v", err)
		return
	}
	l.eb.Publish("agent.dns", "dns_listener", "query", map[string]interface{}{
		"data":      string(decrypted),
		"remote":    remoteAddr.String(),
	})
	response, err := l.crypto.EncryptPayload([]byte("ok"))
	if err != nil {
		l.log.Error("encrypt DNS response: %v", err)
		return
	}
	l.conn.WriteTo(response, remoteAddr)
}

func (l *DNSListener) Stop() {
	l.mu.Lock()
	l.status = "stopped"
	l.mu.Unlock()
	if l.cancel != nil {
		l.cancel()
	}
	if l.conn != nil {
		l.conn.Close()
	}
}

func (l *DNSListener) Type() string {
	return "dns"
}

func (l *DNSListener) Status() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.status
}

type WSSListener struct {
	mu       sync.RWMutex
	status   string
	addr     string
	port     int
	server   *http.Server
	crypto   *ServerCrypto
	eb       *eventbus.EventBus
	log      *logger.Logger
	clients  map[string]net.Conn
	clientsMu sync.RWMutex
}

func NewWSSListener(addr string, port int, crypto *ServerCrypto, eb *eventbus.EventBus, log *logger.Logger) *WSSListener {
	return &WSSListener{
		status:  "stopped",
		addr:    addr,
		port:    port,
		crypto:  crypto,
		eb:      eb,
		log:     log,
		clients: make(map[string]net.Conn),
	}
}

func (l *WSSListener) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", l.handleWebSocket)
	addr := fmt.Sprintf("%s:%d", l.addr, l.port)
	l.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	l.mu.Lock()
	l.status = "running"
	l.mu.Unlock()
	l.log.Info("WSS listener starting on %s", addr)
	go func() {
		if err := l.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			l.log.Error("WSS listener error: %v", err)
		}
	}()
	return nil
}

func (l *WSSListener) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := l.upgradeConnection(w, r)
	if err != nil {
		l.log.Error("upgrade WebSocket: %v", err)
		return
	}
	clientID := fmt.Sprintf("%s:%d", conn.RemoteAddr().Network(), time.Now().UnixNano())
	l.clientsMu.Lock()
	l.clients[clientID] = conn
	l.clientsMu.Unlock()
	defer func() {
		l.clientsMu.Lock()
		delete(l.clients, clientID)
		l.clientsMu.Unlock()
		conn.Close()
	}()
	l.eb.Publish("agent.connect", "wss_listener", "connection", map[string]interface{}{
		"client_id": clientID,
	})
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		decrypted, err := l.crypto.DecryptPayload(data)
		if err != nil {
			l.log.Error("decrypt WSS data: %v", err)
			continue
		}
		l.eb.Publish("agent.message", "wss_listener", "message", map[string]interface{}{
			"client_id": clientID,
			"data":      string(decrypted),
		})
		response, err := l.crypto.EncryptPayload([]byte("ok"))
		if err != nil {
			l.log.Error("encrypt WSS response: %v", err)
			continue
		}
		conn.Write(response)
	}
}

func (l *WSSListener) upgradeConnection(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("hijacking not supported")
	}
	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}
handshake := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	conn.Write([]byte(handshake))
	_ = bufrw
	return conn, nil
}

func (l *WSSListener) Stop() {
	l.mu.Lock()
	l.status = "stopped"
	l.mu.Unlock()
	l.clientsMu.Lock()
	for id, conn := range l.clients {
		conn.Close()
		delete(l.clients, id)
	}
	l.clientsMu.Unlock()
	if l.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		l.server.Shutdown(ctx)
	}
}

func (l *WSSListener) Type() string {
	return "wss"
}

func (l *WSSListener) Status() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.status
}

type ListenerManager struct {
	mu        sync.RWMutex
	listeners []Listener
	log       *logger.Logger
}

func NewListenerManager(log *logger.Logger) *ListenerManager {
	return &ListenerManager{
		log: log,
	}
}

func (lm *ListenerManager) Add(l Listener) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.listeners = append(lm.listeners, l)
}

func (lm *ListenerManager) StartAll() error {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	for _, l := range lm.listeners {
		if err := l.Start(); err != nil {
			return fmt.Errorf("start %s listener: %w", l.Type(), err)
		}
	}
	return nil
}

func (lm *ListenerManager) StopAll() {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	for _, l := range lm.listeners {
		l.Stop()
	}
}

func (lm *ListenerManager) GetByType(listenerType string) []Listener {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	var result []Listener
	for _, l := range lm.listeners {
		if l.Type() == listenerType {
			result = append(result, l)
		}
	}
	return result
}

func (lm *ListenerManager) GetAll() []Listener {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	result := make([]Listener, len(lm.listeners))
	copy(result, lm.listeners)
	return result
}
