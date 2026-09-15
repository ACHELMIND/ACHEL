package cachesmuggle

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(CacheSmuggleConfig{
		TargetURL: "https://target.com",
		CDNType:   "cloudflare",
	})
}

func TestRequestSmuggle(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.RequestSmuggle("https://target.com")
	if err != nil {
		t.Fatalf("RequestSmuggle failed: %v", err)
	}
	if !result.Success {
		t.Error("RequestSmuggle reported failure")
	}
	if result.Method != "Request_Smuggle" {
		t.Errorf("expected method Request_Smuggle, got %s", result.Method)
	}
	if result.Risk != "critical" {
		t.Errorf("expected critical risk, got %s", result.Risk)
	}
}

func TestRequestSmuggleVariants(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.RequestSmuggle("https://target.com")
	if err != nil {
		t.Fatalf("RequestSmuggle failed: %v", err)
	}
	if !strings.Contains(result.Payload, "CL-TE") {
		t.Error("should contain CL-TE variant")
	}
	if !strings.Contains(result.Payload, "TE-CL") {
		t.Error("should contain TE-CL variant")
	}
}

func TestResponseSplit(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.ResponseSplit("https://target.com")
	if err != nil {
		t.Fatalf("ResponseSplit failed: %v", err)
	}
	if !result.Success {
		t.Error("ResponseSplit reported failure")
	}
	if result.Method != "Response_Split" {
		t.Errorf("expected method Response_Split, got %s", result.Method)
	}
}

func TestCacheKeyPoison(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CacheKeyPoison("https://target.com")
	if err != nil {
		t.Fatalf("CacheKeyPoison failed: %v", err)
	}
	if !result.Success {
		t.Error("CacheKeyPoison reported failure")
	}
	if !strings.Contains(result.Payload, "utm_source") {
		t.Error("should contain utm_source param")
	}
}

func TestCDNAbuseCloudflare(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CDNAbuse("cloudflare")
	if err != nil {
		t.Fatalf("CDNAbuse failed: %v", err)
	}
	if !result.Success {
		t.Error("CDNAbuse reported failure")
	}
	if !strings.Contains(result.Payload, "X-Forwarded-Host") {
		t.Error("should mention X-Forwarded-Host")
	}
}

func TestCDNAbuseAkamai(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CDNAbuse("akamai")
	if err != nil {
		t.Fatalf("CDNAbuse failed: %v", err)
	}
	if !strings.Contains(result.Payload, "EdgeKV") {
		t.Error("should mention EdgeKV")
	}
}

func TestCDNAbuseCloudFront(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CDNAbuse("cloudfront")
	if err != nil {
		t.Fatalf("CDNAbuse failed: %v", err)
	}
	if !strings.Contains(result.Payload, "Lambda@Edge") {
		t.Error("should mention Lambda@Edge")
	}
}

func TestAnalyzeCacheHeaders(t *testing.T) {
	eng := newTestEngine()
	headers := map[string]string{
		"X-Forwarded-Host": "evil.com",
		"Cache-Control":    "max-age=3600",
		"X-Custom-Header":  "value",
	}
	result := eng.AnalyzeCacheHeaders(headers)
	if len(result) != 3 {
		t.Errorf("expected 3 headers, got %d", len(result))
	}
	foundUnkeyed := false
	for _, h := range result {
		if h.Unkeyed {
			foundUnkeyed = true
		}
	}
	if !foundUnkeyed {
		t.Error("should detect unkeyed header")
	}
}

func TestDetectCDN(t *testing.T) {
	eng := newTestEngine()
	tests := []struct {
		headers map[string]string
		want    string
	}{
		{map[string]string{"CF-Ray": "123"}, "Cloudflare"},
		{map[string]string{"X-Akamai-Session-ID": "abc"}, "Akamai"},
		{map[string]string{"X-Amz-Cf-Pop": "IAD"}, "CloudFront"},
		{map[string]string{"X-Custom": "value"}, "Unknown"},
	}
	for _, tt := range tests {
		got := eng.DetectCDN(tt.headers)
		if got != tt.want {
			t.Errorf("DetectCDN(%v) = %s, want %s", tt.headers, got, tt.want)
		}
	}
}
