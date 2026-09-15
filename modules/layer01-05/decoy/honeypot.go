package decoy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type Honeypot struct {
	mu          sync.RWMutex
	id          string
	type_       string
	addr        string
	port        int
	running     bool
	logEntries  []LogEntry
	connections map[string]*Connection
}

type LogEntry struct {
	Timestamp time.Time
	IP        string
	Action    string
	Details   string
	Severity  string
}

type Connection struct {
	ID        string
	IP        string
	Port      int
	Protocol  string
	StartTime time.Time
	Active    bool
}

type HoneypotConfig struct {
	Type string
	Addr string
	Port int
}

func NewHoneypot(config HoneypotConfig) *Honeypot {
	return &Honeypot{
		id:          generateHoneypotID(),
		type_:       config.Type,
		addr:        config.Addr,
		port:        config.Port,
		connections: make(map[string]*Connection),
	}
}

func (h *Honeypot) Start() error {
	h.mu.Lock()
	h.running = true
	h.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleRoot)
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/admin", h.handleAdmin)
	mux.HandleFunc("/ssh", h.handleSSH)
	mux.HandleFunc("/ftp", h.handleFTP)
	mux.HandleFunc("/mysql", h.handleMySQL)

	addr := fmt.Sprintf("%s:%d", h.addr, h.port)
	log.Printf("Starting honeypot %s on %s", h.type_, addr)

	return http.ListenAndServe(addr, mux)
}

func (h *Honeypot) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.running = false
}

func (h *Honeypot) handleRoot(w http.ResponseWriter, r *http.Request) {
	h.logActivity(r.RemoteAddr, "access", "root page", "low")
	h.serveDecoyPage(w, r)
}

func (h *Honeypot) handleLogin(w http.ResponseWriter, r *http.Request) {
	h.logActivity(r.RemoteAddr, "login_attempt", "login page", "medium")

	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		h.mu.Lock()
		h.connections[r.RemoteAddr] = &Connection{
			ID:        generateConnID(),
			IP:        r.RemoteAddr,
			Protocol:  "HTTP",
			StartTime: time.Now(),
			Active:    true,
		}
		h.mu.Unlock()

		log.Printf("Honeypot credential captured: %s:%s from %s", username, password, r.RemoteAddr)
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<html><head><title>Login</title></head>
<body><h1>Secure Login</h1>
<form method="POST">
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<button type="submit">Login</button>
</form></body></html>`)
}

func (h *Honeypot) handleAdmin(w http.ResponseWriter, r *http.Request) {
	h.logActivity(r.RemoteAddr, "admin_access", "admin page", "high")
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (h *Honeypot) handleSSH(w http.ResponseWriter, r *http.Request) {
	h.logActivity(r.RemoteAddr, "ssh_attempt", "SSH endpoint", "high")
	w.WriteHeader(http.StatusServiceUnavailable)
}

func (h *Honeypot) handleFTP(w http.ResponseWriter, r *http.Request) {
	h.logActivity(r.RemoteAddr, "ftp_attempt", "FTP endpoint", "high")
	w.WriteHeader(http.StatusServiceUnavailable)
}

func (h *Honeypot) handleMySQL(w http.ResponseWriter, r *http.Request) {
	h.logActivity(r.RemoteAddr, "mysql_attempt", "MySQL endpoint", "high")
	w.WriteHeader(http.StatusServiceUnavailable)
}

func (h *Honeypot) serveDecoyPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Apache/2.4.52 (Ubuntu)")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<html><head><title>Welcome</title></head>
<body><h1>Welcome to our website</h1>
<p>This page is under construction.</p></body></html>`)
}

func (h *Honeypot) logActivity(ip, action, details, severity string) {
	entry := LogEntry{
		Timestamp: time.Now(),
		IP:        ip,
		Action:    action,
		Details:   details,
		Severity:  severity,
	}

	h.mu.Lock()
	h.logEntries = append(h.logEntries, entry)
	h.mu.Unlock()

	log.Printf("Honeypot [%s] %s from %s: %s (severity: %s)", h.type_, action, ip, details, severity)
}

func (h *Honeypot) GetLogEntries() []LogEntry {
	h.mu.RLock()
	defer h.mu.RUnlock()

	entries := make([]LogEntry, len(h.logEntries))
	copy(entries, h.logEntries)
	return entries
}

func (h *Honeypot) GetConnections() []*Connection {
	h.mu.RLock()
	defer h.mu.RUnlock()

	conns := make([]*Connection, 0, len(h.connections))
	for _, conn := range h.connections {
		conns = append(conns, conn)
	}
	return conns
}

func (h *Honeypot) GetID() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.id
}

func (h *Honeypot) GetType() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.type_
}

func (h *Honeypot) IsRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}

func generateHoneypotID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateConnID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
