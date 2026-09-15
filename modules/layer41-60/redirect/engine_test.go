package redirect

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(RedirectConfig{
		TargetURL:     "https://target.com/login",
		RedirectParam: "next",
		AllowedDomains: []string{"target.com", "app.target.com"},
	})
}

func TestParamManipulation(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.ParamManipulation("https://target.com/login?next=", "https://evil.com")
	if err != nil {
		t.Fatalf("ParamManipulation failed: %v", err)
	}
	if !result.Success {
		t.Error("ParamManipulation reported failure")
	}
	if result.Method != "Param_Manipulation" {
		t.Errorf("expected method Param_Manipulation, got %s", result.Method)
	}
	if len(result.Payload) == 0 {
		t.Error("payload is empty")
	}
}

func TestDoubleURLEncode(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.DoubleURLEncode("https://evil.com/steal?token=abc")
	if err != nil {
		t.Fatalf("DoubleURLEncode failed: %v", err)
	}
	if !result.Success {
		t.Error("DoubleURLEncode reported failure")
	}
	if !strings.Contains(result.Payload, "evil.com") {
		t.Error("payload should contain original URL")
	}
}

func TestProtocolRelative(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.ProtocolRelative("https://evil.com/steal")
	if err != nil {
		t.Fatalf("ProtocolRelative failed: %v", err)
	}
	if !result.Success {
		t.Error("ProtocolRelative reported failure")
	}
	if !strings.Contains(result.Payload, "//") {
		t.Error("payload should contain protocol-relative URL")
	}
}

func TestPhishRedirect(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.PhishRedirect("https://target.com", "evil-target.com")
	if err != nil {
		t.Fatalf("PhishRedirect failed: %v", err)
	}
	if !result.Success {
		t.Error("PhishRedirect reported failure")
	}
	if result.Risk != "critical" {
		t.Errorf("expected critical risk, got %s", result.Risk)
	}
	if !strings.Contains(result.Payload, "evil-target.com") {
		t.Error("payload missing phishing domain")
	}
}

func TestOAuthTokenLeak(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.OAuthTokenLeak("auth.example.com", "client-123", "https://evil.com/callback")
	if err != nil {
		t.Fatalf("OAuthTokenLeak failed: %v", err)
	}
	if !result.Success {
		t.Error("OAuthTokenLeak reported failure")
	}
	if result.Method != "OAuth_Token_Leak" {
		t.Errorf("expected method OAuth_Token_Leak, got %s", result.Method)
	}
}

func TestAnalyzeRedirectURL(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.AnalyzeRedirectURL("https://target.com/path?key=val#section")
	if err != nil {
		t.Fatalf("AnalyzeRedirectURL failed: %v", err)
	}
	if result.Host != "target.com" {
		t.Errorf("expected host target.com, got %s", result.Host)
	}
	if result.Params["key"] != "val" {
		t.Errorf("expected param key=val, got %s", result.Params["key"])
	}
	if result.Fragment != "section" {
		t.Errorf("expected fragment section, got %s", result.Fragment)
	}
}

func TestDetectOpenRedirect(t *testing.T) {
	eng := newTestEngine()

	found, msg := eng.DetectOpenRedirect("https://target.com/login?next=https://evil.com")
	if !found {
		t.Error("should detect open redirect")
	}
	if !strings.Contains(msg, "next") {
		t.Error("should mention the parameter")
	}

	found, _ = eng.DetectOpenRedirect("https://target.com/login?user=admin")
	if found {
		t.Error("should not detect open redirect for user param")
	}
}

func TestGenerateRedirectChain(t *testing.T) {
	eng := newTestEngine()
	chain := eng.GenerateRedirectChain([]string{
		"https://start.com",
		"https://middle.com",
		"https://end.com",
	})
	if chain.Total != 3 {
		t.Errorf("expected 3 steps, got %d", chain.Total)
	}
	if chain.Steps[0].StatusCode != 302 {
		t.Errorf("expected 302 for first step, got %d", chain.Steps[0].StatusCode)
	}
	if chain.Steps[2].StatusCode != 200 {
		t.Errorf("expected 200 for last step, got %d", chain.Steps[2].StatusCode)
	}
}
