package gateway

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type Middleware interface {
	Wrap(next http.Handler) http.Handler
}

type Gateway struct {
	config     *Config
	server     *http.Server
	middleware  []Middleware
	routes     map[string]http.Handler
	methods    map[string]map[string]http.Handler
	mu         sync.RWMutex
	startTime  time.Time
	totalReqs  uint64
	totalErrs  uint64
}

type Config struct {
	Addr            string        `json:"addr"`
	Port            int           `json:"port"`
	ReadTimeout     time.Duration `json:"read_timeout"`
	WriteTimeout    time.Duration `json:"write_timeout"`
	MaxHeaderBytes  int           `json:"max_header_bytes"`
	EnableTLS       bool          `json:"enable_tls"`
	TLSCertFile     string        `json:"tls_cert_file"`
	TLSKeyFile      string        `json:"tls_key_file"`
	RateLimit       int           `json:"rate_limit"`
	MaxConns        int           `json:"max_conns"`
	CORSOrigin      string        `json:"cors_origin"`
	JWTSecret       string        `json:"jwt_secret"`
	JWTExpiry       time.Duration `json:"jwt_expiry"`
	EnableRBAC      bool          `json:"enable_rbac"`
	EnableMetrics   bool          `json:"enable_metrics"`
}

func DefaultConfig() *Config {
	return &Config{
		Addr:           "0.0.0.0",
		Port:           3000,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		MaxHeaderBytes: 1 << 20,
		RateLimit:      100,
		MaxConns:       1000,
		JWTExpiry:      24 * time.Hour,
		EnableRBAC:     true,
		EnableMetrics:  true,
	}
}

type loggingMiddleware struct{}
type recoveryMiddleware struct{}
type corsMiddleware struct{ Origin string }
type rateLimitMiddleware struct{ Rate int }
type requestIDMiddleware struct{}
type metricsMiddleware struct{}

func (m *loggingMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func (m *recoveryMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("PANIC: %v", err)
				http.Error(w, `{"error":"internal_server_error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (m *corsMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := m.Origin
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *rateLimitMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "100")
		next.ServeHTTP(w, r)
	})
}

func (m *requestIDMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", time.Now().Format("20060102150405.000000000"))
		next.ServeHTTP(w, r)
	})
}

func (m *metricsMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func New(cfg *Config) *Gateway {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	gw := &Gateway{
		config:    cfg,
		routes:    make(map[string]http.Handler),
		methods:   make(map[string]map[string]http.Handler),
		startTime: time.Now(),
	}

	gw.middleware = []Middleware{
		&loggingMiddleware{},
		&recoveryMiddleware{},
		&corsMiddleware{Origin: cfg.CORSOrigin},
		&rateLimitMiddleware{Rate: cfg.RateLimit},
		&requestIDMiddleware{},
		&metricsMiddleware{},
	}

	gw.setupRoutes()

	mux := http.NewServeMux()
	for path, handler := range gw.routes {
		mux.Handle(path, handler)
	}

	gw.server = &http.Server{
		Addr:           fmt.Sprintf("%s:%d", cfg.Addr, cfg.Port),
		Handler:        gw.chainMiddleware(mux),
		ReadTimeout:    cfg.ReadTimeout,
		WriteTimeout:   cfg.WriteTimeout,
		MaxHeaderBytes: cfg.MaxHeaderBytes,
	}

	return gw
}

func (gw *Gateway) setupRoutes() {
	gw.routes["/api/v1/health"] = http.HandlerFunc(gw.handleHealth)
	gw.routes["/api/v1/auth/login"] = http.HandlerFunc(gw.handleLogin)
	gw.routes["/api/v1/auth/logout"] = http.HandlerFunc(gw.handleLogout)
	gw.routes["/api/v1/auth/refresh"] = http.HandlerFunc(gw.handleRefresh)
	gw.routes["/api/v1/agents"] = http.HandlerFunc(gw.handleAgents)
	gw.routes["/api/v1/tasks"] = http.HandlerFunc(gw.handleTasks)
	gw.routes["/api/v1/results"] = http.HandlerFunc(gw.handleResults)
	gw.routes["/api/v1/reports"] = http.HandlerFunc(gw.handleReports)
	gw.routes["/api/v1/stats"] = http.HandlerFunc(gw.handleStats)
	gw.routes["/api/v1/activity"] = http.HandlerFunc(gw.handleActivity)
	gw.routes["/ws"] = http.HandlerFunc(gw.handleWebSocket)
}

func (gw *Gateway) chainMiddleware(next http.Handler) http.Handler {
	for i := len(gw.middleware) - 1; i >= 0; i-- {
		next = gw.middleware[i].Wrap(next)
	}
	return next
}

func (gw *Gateway) Start() error {
	log.Printf("API Gateway starting on %s:%d", gw.config.Addr, gw.config.Port)
	return gw.server.ListenAndServe()
}

func (gw *Gateway) Stop() error {
	return gw.server.Close()
}

func (gw *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"healthy","uptime":"%s"}`, time.Since(gw.startTime).String())
}

func (gw *Gateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"token":"jwt-token-placeholder","expires_in":86400}`)
}

func (gw *Gateway) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"logged_out"}`)
}

func (gw *Gateway) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"token":"refreshed-jwt-token","expires_in":86400}`)
}

func (gw *Gateway) handleAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		fmt.Fprintf(w, `{"agents":[]}`)
	case http.MethodPost:
		fmt.Fprintf(w, `{"status":"agent_registered"}`)
	case http.MethodDelete:
		fmt.Fprintf(w, `{"status":"all_agents_killed"}`)
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (gw *Gateway) handleTasks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		fmt.Fprintf(w, `{"tasks":[]}`)
	case http.MethodPost:
		fmt.Fprintf(w, `{"status":"task_created"}`)
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (gw *Gateway) handleResults(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"results":[]}`)
}

func (gw *Gateway) handleReports(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"reports":[]}`)
}

func (gw *Gateway) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"active_agents":0,"pending_tasks":0,"completed_tasks":0,"credentials_found":0}`)
}

func (gw *Gateway) handleActivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"activities":[]}`)
}

func (gw *Gateway) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"websocket_endpoint"}`)
}

func (gw *Gateway) IncrementRequests() {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.totalReqs++
}
