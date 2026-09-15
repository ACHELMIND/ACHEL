package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoggingMiddleware(t *testing.T) {
	m := &LoggingMiddleware{}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := m.Wrap(next)
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if !called {
		t.Error("next handler was not called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	m := &RecoveryMiddleware{}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := m.Wrap(next)
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if !called {
		t.Error("next handler was not called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestRecoveryMiddleware_PanicRecovery(t *testing.T) {
	m := &RecoveryMiddleware{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	wrapped := m.Wrap(next)
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	// Should not panic
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestCORSMiddleware(t *testing.T) {
	m := &CORSMiddleware{Origin: "https://example.com"}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := m.Wrap(next)
	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("CORS origin = %q, want %q", rr.Header().Get("Access-Control-Allow-Origin"), "https://example.com")
	}
	if rr.Header().Get("Access-Control-Allow-Methods") != "GET, POST, PUT, DELETE, OPTIONS" {
		t.Error("CORS methods not set correctly")
	}
}

func TestCORSMiddleware_DefaultOrigin(t *testing.T) {
	m := &CORSMiddleware{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := m.Wrap(next)
	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("CORS default origin = %q, want %q", rr.Header().Get("Access-Control-Allow-Origin"), "*")
	}
}

func TestCORSMiddleware_OptionsRequest(t *testing.T) {
	m := &CORSMiddleware{Origin: "https://example.com"}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	wrapped := m.Wrap(next)
	req := httptest.NewRequest("OPTIONS", "/api/test", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if called {
		t.Error("next handler should not be called for OPTIONS")
	}
	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	m := &RateLimitMiddleware{Rate: 100}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := m.Wrap(next)
	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Header().Get("X-RateLimit-Limit") != "100" {
		t.Errorf("RateLimit-Limit = %q, want %q", rr.Header().Get("X-RateLimit-Limit"), "100")
	}
}

func TestRequestIDMiddleware_GeneratesID(t *testing.T) {
	m := &RequestIDMiddleware{}
	var receivedID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	})

	wrapped := m.Wrap(next)
	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if receivedID == "" {
		t.Error("request ID should be generated")
	}
	if rr.Header().Get("X-Request-ID") != receivedID {
		t.Error("response header X-Request-ID should match")
	}
}

func TestRequestIDMiddleware_PreservesExistingID(t *testing.T) {
	m := &RequestIDMiddleware{}
	var receivedID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	})

	wrapped := m.Wrap(next)
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-Request-ID", "my-custom-id")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if receivedID != "my-custom-id" {
		t.Errorf("request ID = %q, want %q", receivedID, "my-custom-id")
	}
}

func TestResponseWriter(t *testing.T) {
	rr := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}

	rw.WriteHeader(http.StatusNotFound)

	if rw.statusCode != http.StatusNotFound {
		t.Errorf("statusCode = %d, want %d", rw.statusCode, http.StatusNotFound)
	}
	if rr.Code != http.StatusNotFound {
		t.Errorf("recorder code = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestMetricsMiddleware(t *testing.T) {
	m := &MetricsMiddleware{}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := m.Wrap(next)
	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if !called {
		t.Error("next handler was not called")
	}
}

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	if id1 == "" {
		t.Error("request ID should not be empty")
	}
	if id1 != id2 {
		// IDs can differ if called at different times
		t.Logf("IDs differ (expected): %s vs %s", id1, id2)
	}
}
