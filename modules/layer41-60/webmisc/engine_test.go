package webmisc

import (
	"net/http"
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(WebMiscConfig{
		TargetURL:  "https://target.com",
		BackendURL: "http://127.0.0.1:8080",
		HostHeader: "target.com",
	})
}

func TestCachePoisoning(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CachePoisoning("https://target.com")
	if err != nil {
		t.Fatalf("CachePoisoning failed: %v", err)
	}
	if !result.Success {
		t.Error("CachePoisoning reported failure")
	}
	if result.Method != "Cache_Poisoning" {
		t.Errorf("expected method Cache_Poisoning, got %s", result.Method)
	}
	if len(result.Payload) == 0 {
		t.Error("payload is empty")
	}
}

func TestWebTakeover(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.WebTakeover("https://target.com")
	if err != nil {
		t.Fatalf("WebTakeover failed: %v", err)
	}
	if !result.Success {
		t.Error("WebTakeover reported failure")
	}
	if result.Method != "Web_Takeover" {
		t.Errorf("expected method Web_Takeover, got %s", result.Method)
	}
}

func TestHTTPSmuggling(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.HTTPSmuggling("https://target.com")
	if err != nil {
		t.Fatalf("HTTPSmuggling failed: %v", err)
	}
	if !result.Success {
		t.Error("HTTPSmuggling reported failure")
	}
	if result.Method != "HTTP_Smuggling" {
		t.Errorf("expected method HTTP_Smuggling, got %s", result.Method)
	}
	if result.Risk != "critical" {
		t.Errorf("expected critical risk, got %s", result.Risk)
	}
}

func TestCLVSDetect(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CLVSDetect("https://target.com")
	if err != nil {
		t.Fatalf("CLVSDetect failed: %v", err)
	}
	if !result.Success {
		t.Error("CLVSDetect reported failure")
	}
	if !strings.Contains(result.Payload, "CL/VS") {
		t.Error("payload should contain detection info")
	}
}

func TestAnalyzeHeaders(t *testing.T) {
	eng := newTestEngine()
	headers := http.Header{}
	headers.Set("X-Frame-Options", "DENY")
	headers.Set("Server", "nginx/1.18")
	headers.Set("Content-Type", "text/html")

	analysis := eng.AnalyzeHeaders(headers)
	if analysis["X-Frame-Options"] != "DENY" {
		t.Errorf("expected DENY, got %s", analysis["X-Frame-Options"])
	}
	if analysis["Server"] != "nginx/1.18" {
		t.Errorf("expected nginx/1.18, got %s", analysis["Server"])
	}
	if analysis["X-Content-Type-Options"] != "MISSING" {
		t.Error("expected MISSING for unset header")
	}
}

func TestDetectTech(t *testing.T) {
	eng := newTestEngine()
	headers := http.Header{}
	headers.Set("X-Powered-By", "PHP/8.0")
	body := `<html><link href="/wp-content/themes/style.css"></html>`

	techs := eng.DetectTech(headers, body)
	hasPHP := false
	hasWP := false
	for _, tech := range techs {
		if strings.Contains(tech, "PHP") {
			hasPHP = true
		}
		if tech == "WordPress" {
			hasWP = true
		}
	}
	if !hasPHP {
		t.Error("should detect PHP from X-Powered-By")
	}
	if !hasWP {
		t.Error("should detect WordPress from body")
	}
}

func TestDetectTechDjango(t *testing.T) {
	eng := newTestEngine()
	headers := http.Header{}
	body := "csrfmiddlewaretoken: abc123 and django framework detected"
	techs := eng.DetectTech(headers, body)
	found := false
	for _, tech := range techs {
		if tech == "Django" {
			found = true
		}
	}
	if !found {
		t.Error("should detect Django from body")
	}
}
