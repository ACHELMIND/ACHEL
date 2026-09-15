package cachesmuggle

import "time"

type CacheSmuggleConfig struct {
	TargetURL  string        `json:"target_url"`
	CDNType    string        `json:"cdn_type"`
	Timeout    time.Duration `json:"timeout"`
}

type CacheSmuggleResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Payload  string        `json:"payload"`
	Risk     string        `json:"risk"`
}

type SmuggleVariant struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Technique   string `json:"technique"`
	Complexity  string `json:"complexity"`
}

type CacheHeader struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Unkeyed bool   `json:"unkeyed"`
}

type RequestSmuggleResult struct {
	Variant    string `json:"variant"`
	CLValue    string `json:"cl_value"`
	TEValue    string `json:"te_value"`
	Payload    string `json:"payload"`
}

type ResponseSplitResult struct {
	Header      string `json:"header"`
	Body        string `json:"body"`
	CacheBuster bool   `json:"cache_buster"`
}

type CacheKeyPoisonResult struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	UnkeyedParam string `json:"unkeyed_param"`
	Affected    bool   `json:"affected"`
}

type CDNInfo struct {
	Type           string   `json:"type"`
	Vulnerable     bool     `json:"vulnerable"`
	UnkeyedHeaders []string `json:"unkeyed_headers"`
}
