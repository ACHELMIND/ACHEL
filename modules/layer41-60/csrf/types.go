package csrf

import "time"

type CSRFConfig struct {
	TargetURL    string        `json:"target_url"`
	TokenName    string        `json:"token_name"`
	CookieDomain string        `json:"cookie_domain"`
	Origin       string        `json:"origin"`
	Timeout      time.Duration `json:"timeout"`
}

type CSRFResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Payload  string        `json:"payload"`
	Risk     string        `json:"risk"`
}

type CSRFMethod struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Complexity   string `json:"complexity"`
	Reliability  string `json:"reliability"`
}

type CSRFTarget struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Parameters  map[string]string `json:"parameters"`
	Headers     map[string]string `json:"headers"`
	Cookies     map[string]string `json:"cookies"`
	TokenField  string            `json:"token_field"`
}

type CSRFToken struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Length   int    `json:"length"`
	Entropy  int    `json:"entropy"`
	Pattern  string `json:"pattern"`
}

type SameSiteConfig struct {
	CookieName   string `json:"cookie_name"`
	SameSite     string `json:"samesite"`
	Secure       bool   `json:"secure"`
	HttpOnly     bool   `json:"http_only"`
	Path         string `json:"path"`
}

type RefererCheck struct {
	AllowedDomains []string `json:"allowed_domains"`
	Strict         bool     `json:"strict"`
	IgnorePath     bool     `json:"ignore_path"`
	IgnoreQuery    bool     `json:"ignore_query"`
}

type CSRFHTML struct {
	Action    string            `json:"action"`
	Method    string            `json:"method"`
	Fields    map[string]string `json:"fields"`
	AutoSubmit bool             `json:"auto_submit"`
}

type JSONCSRFPayload struct {
	URL       string            `json:"url"`
	ContentType string          `json:"content_type"`
	Body      map[string]string `json:"body"`
	Method    string            `json:"method"`
}
