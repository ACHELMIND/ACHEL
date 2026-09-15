package webmisc

import "time"

type WebMiscConfig struct {
	TargetURL    string        `json:"target_url"`
	BackendURL   string        `json:"backend_url"`
	HostHeader   string        `json:"host_header"`
	Timeout      time.Duration `json:"timeout"`
}

type WebMiscResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Payload  string        `json:"payload"`
	Risk     string        `json:"risk"`
}

type CachePoisonMethod struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Header      string `json:"header"`
	Value       string `json:"value"`
}

type SmuggleType struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Technique   string `json:"technique"`
}

type CachePoisonResult struct {
	Key          string `json:"key"`
	Value        string `json:"value"`
	CacheHit     bool   `json:"cache_hit"`
	TTL          int    `json:"ttl"`
	UnkeyedParam string `json:"unkeyed_param"`
}

type TakeoverResult struct {
	Vulnerable   bool   `json:"vulnerable"`
	CNAME        string `json:"cname"`
	Platform     string `json:"platform"`
	Status       string `json:"status"`
	TakeoverURL  string `json:"takeover_url"`
}

type SmuggleRequest struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	Payload  string            `json:"payload"`
}

type CLTEResult struct {
	CLLength   int    `json:"cl_length"`
	TELength   string `json:"te_length"`
	Vulnerable bool   `json:"vulnerable"`
	Technique  string `json:"technique"`
}

type WebFingerprint struct {
	Server      string            `json:"server"`
	Technology  []string          `json:"technology"`
	Headers     map[string]string `json:"headers"`
	Cookies     []string          `json:"cookies"`
	Paths       []string          `json:"paths"`
}
