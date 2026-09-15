package decoy

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type DecoyServer struct {
	mu          sync.RWMutex
	addr        string
	port        int
	running     bool
	visitors    []Visitor
	harvestData map[string][]string
}

type Visitor struct {
	IP        string
	UserAgent string
	Path      string
	Timestamp time.Time
	Headers   map[string]string
}

func NewDecoyServer(addr string, port int) *DecoyServer {
	return &DecoyServer{
		addr:        addr,
		port:        port,
		harvestData: make(map[string][]string),
	}
}

func (d *DecoyServer) Start() error {
	d.mu.Lock()
	d.running = true
	d.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleRoot)
	mux.HandleFunc("/login", d.handleLogin)
	mux.HandleFunc("/admin", d.handleAdmin)
	mux.HandleFunc("/api", d.handleAPI)

	addr := fmt.Sprintf("%s:%d", d.addr, d.port)
	log.Printf("Starting decoy server on %s", addr)

	return http.ListenAndServe(addr, mux)
}

func (d *DecoyServer) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.running = false
}

func (d *DecoyServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	d.logVisitor(r)
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<html><head><title>Welcome</title></head>
<body><h1>Welcome to our website</h1>
<p>This page is under construction.</p></body></html>`)
}

func (d *DecoyServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	d.logVisitor(r)

	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		d.mu.Lock()
		d.harvestData["credentials"] = append(d.harvestData["credentials"],
			fmt.Sprintf("%s:%s", username, password))
		d.mu.Unlock()

		log.Printf("Credential harvested: %s:%s", username, password)
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<html><head><title>Login</title></head>
<body><h1>Login</h1>
<form method="POST">
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<button type="submit">Login</button>
</form></body></html>`)
}

func (d *DecoyServer) handleAdmin(w http.ResponseWriter, r *http.Request) {
	d.logVisitor(r)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (d *DecoyServer) handleAPI(w http.ResponseWriter, r *http.Request) {
	d.logVisitor(r)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "ok"}`)
}

func (d *DecoyServer) logVisitor(r *http.Request) {
	visitor := Visitor{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
		Path:      r.URL.Path,
		Timestamp: time.Now(),
		Headers:   make(map[string]string),
	}

	for key, values := range r.Header {
		if len(values) > 0 {
			visitor.Headers[key] = values[0]
		}
	}

	d.mu.Lock()
	d.visitors = append(d.visitors, visitor)
	d.mu.Unlock()
}

func (d *DecoyServer) GetVisitors() []Visitor {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.visitors
}

func (d *DecoyServer) GetHarvestedData() map[string][]string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.harvestData
}
