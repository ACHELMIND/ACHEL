package csrf

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(CSRFConfig{
		TargetURL:    "https://target.com/api/action",
		TokenName:    "csrf_token",
		CookieDomain: "target.com",
		Origin:       "https://attacker.com",
	})
}

func TestTokenBypass(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.TokenBypass("csrf_token", "abc123")
	if err != nil {
		t.Fatalf("TokenBypass failed: %v", err)
	}
	if !result.Success {
		t.Error("TokenBypass reported failure")
	}
	if result.Method != "Token_Bypass" {
		t.Errorf("expected method Token_Bypass, got %s", result.Method)
	}
}

func TestTokenBypassLowEntropy(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.TokenBypass("csrf_token", "123456")
	if err != nil {
		t.Fatalf("TokenBypass failed: %v", err)
	}
	if !strings.Contains(result.Message, "numeric") {
		t.Error("should detect numeric pattern")
	}
}

func TestRefererBypass(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.RefererBypass([]string{"target.com", "app.target.com"})
	if err != nil {
		t.Fatalf("RefererBypass failed: %v", err)
	}
	if !result.Success {
		t.Error("RefererBypass reported failure")
	}
	if result.Method != "Referer_Bypass" {
		t.Errorf("expected method Referer_Bypass, got %s", result.Method)
	}
	if len(result.Payload) == 0 {
		t.Error("payload is empty")
	}
}

func TestSameSiteBypassStrict(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.SameSiteBypass("session", "Strict")
	if err != nil {
		t.Fatalf("SameSiteBypass failed: %v", err)
	}
	if !result.Success {
		t.Error("SameSiteBypass reported failure")
	}
	if !strings.Contains(result.Payload, "navigation") {
		t.Error("should include navigation technique")
	}
}

func TestSameSiteBypassLax(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.SameSiteBypass("session", "Lax")
	if err != nil {
		t.Fatalf("SameSiteBypass failed: %v", err)
	}
	if !result.Success {
		t.Error("SameSiteBypass reported failure")
	}
	if !strings.Contains(result.Payload, "GET") {
		t.Error("should include GET technique for Lax")
	}
}

func TestJSONCSRF(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.JSONCSRF("https://target.com/api/update", map[string]string{
		"email": "evil@attacker.com",
		"role":  "admin",
	})
	if err != nil {
		t.Fatalf("JSONCSRF failed: %v", err)
	}
	if !result.Success {
		t.Error("JSONCSRF reported failure")
	}
	if result.Method != "JSON_CSRF" {
		t.Errorf("expected method JSON_CSRF, got %s", result.Method)
	}
	if !strings.Contains(result.Payload, "evil@attacker.com") {
		t.Error("payload missing email")
	}
}

func TestAdminHijack(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.AdminHijack("https://target.com/admin", "admin-token-123")
	if err != nil {
		t.Fatalf("AdminHijack failed: %v", err)
	}
	if !result.Success {
		t.Error("AdminHijack reported failure")
	}
	if result.Method != "Admin_Hijack" {
		t.Errorf("expected method Admin_Hijack, got %s", result.Method)
	}
	if result.Risk != "critical" {
		t.Errorf("expected critical risk, got %s", result.Risk)
	}
}

func TestGenerateCSRFHTML(t *testing.T) {
	eng := newTestEngine()
	html := eng.GenerateCSRFHTML("https://target.com/api", "POST", map[string]string{
		"action": "transfer",
		"amount": "10000",
	})
	if !strings.Contains(html, "target.com/api") {
		t.Error("HTML missing target URL")
	}
	if !strings.Contains(html, "transfer") {
		t.Error("HTML missing action parameter")
	}
	if !strings.Contains(html, "submit") {
		t.Error("HTML missing auto-submit script")
	}
}

func TestGenerateRandomToken(t *testing.T) {
	eng := newTestEngine()
	token1 := eng.GenerateRandomToken(16)
	token2 := eng.GenerateRandomToken(16)
	if token1 == token2 {
		t.Error("random tokens should be different")
	}
	if len(token1) != 32 {
		t.Errorf("expected 32 hex chars, got %d", len(token1))
	}
}

func TestEstimateEntropy(t *testing.T) {
	eng := newTestEngine()
	tests := []struct {
		value string
		min   int
	}{
		{"abc", 0},
		{"1234567890abcdef", 0},
		{"aB3!", 0},
	}
	for _, tt := range tests {
		got := eng.estimateEntropy(tt.value)
		if got < tt.min {
			t.Errorf("estimateEntropy(%q) = %d, want >= %d", tt.value, got, tt.min)
		}
	}
}

func TestDetectPattern(t *testing.T) {
	eng := newTestEngine()
	tests := []struct {
		value, want string
	}{
		{"12345", "numeric"},
		{"abcdef", "alphanumeric"},
		{"abc123DEF", "mixed"},
	}
	for _, tt := range tests {
		got := eng.detectPattern(tt.value)
		if got != tt.want {
			t.Errorf("detectPattern(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}
