package redirect

import "time"

type RedirectConfig struct {
	TargetURL   string        `json:"target_url"`
	RedirectParam string      `json:"redirect_param"`
	AllowedDomains []string   `json:"allowed_domains"`
	Timeout     time.Duration `json:"timeout"`
}

type RedirectResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Payload  string        `json:"payload"`
	Risk     string        `json:"risk"`
}

type RedirectMethod struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Complexity  string `json:"complexity"`
}

type OAuthRedirect struct {
	AuthorizationURL string `json:"authorization_url"`
	RedirectURI      string `json:"redirect_uri"`
	ClientID         string `json:"client_id"`
	State            string `json:"state"`
	Scope            string `json:"scope"`
}

type RedirectURL struct {
	Raw      string            `json:"raw"`
	Scheme   string            `json:"scheme"`
	Host     string            `json:"host"`
	Path     string            `json:"path"`
	Params   map[string]string `json:"params"`
	Fragment string            `json:"fragment"`
}

type BypassPayload struct {
	Encoded    string `json:"encoded"`
	Decoded    string `json:"decoded"`
	Evasion   string `json:"evasion"`
	Technique string `json:"technique"`
}

type RedirectChain struct {
	Steps []RedirectStep `json:"steps"`
	Total int            `json:"total"`
}

type RedirectStep struct {
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code"`
	Location    string `json:"location"`
	NextStep    int    `json:"next_step"`
}
