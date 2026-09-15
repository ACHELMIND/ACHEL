package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGatewayHealth(t *testing.T) {
	gw := New(DefaultConfig())
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	gw.handleHealth(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGatewayAgents(t *testing.T) {
	gw := New(DefaultConfig())
	req := httptest.NewRequest("GET", "/api/v1/agents", nil)
	w := httptest.NewRecorder()
	gw.handleAgents(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGatewayTasks(t *testing.T) {
	gw := New(DefaultConfig())
	req := httptest.NewRequest("GET", "/api/v1/tasks", nil)
	w := httptest.NewRecorder()
	gw.handleTasks(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGatewayStats(t *testing.T) {
	gw := New(DefaultConfig())
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	w := httptest.NewRecorder()
	gw.handleStats(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGatewayLogin(t *testing.T) {
	gw := New(DefaultConfig())
	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	w := httptest.NewRecorder()
	gw.handleLogin(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGatewayMethodNotAllowed(t *testing.T) {
	gw := New(DefaultConfig())
	req := httptest.NewRequest("PATCH", "/api/v1/agents", nil)
	w := httptest.NewRecorder()
	gw.handleAgents(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Port != 3000 {
		t.Errorf("expected port 3000, got %d", cfg.Port)
	}
	if cfg.RateLimit != 100 {
		t.Errorf("expected rate limit 100, got %d", cfg.RateLimit)
	}
}
