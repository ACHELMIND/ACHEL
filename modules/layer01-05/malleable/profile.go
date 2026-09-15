package malleable

import (
	"fmt"
	"net/http"
	"time"
)

type Profile struct {
	Name        string
	Description string
	HTTPGet     HTTPGetConfig
	HTTPPost    HTTPPostConfig
	Metadata    MetadataConfig
	TLS         TLSConfig
}

type HTTPGetConfig struct {
	Method     string
	URI        []string
	Port       []int
	Headers    map[string]string
	PipeNames  []string
	Jitter     float64
}

type HTTPPostConfig struct {
	Method     string
	URI        string
	Port       []int
	Headers    map[string]string
	Output     string
	Jitter     float64
}

type MetadataConfig struct {
	Generic    string
	OS         string
	Arch       string
	Hostname   string
	Username   string
	ExternalIP string
	InternalIP string
	Process    string
	PID        int
}

type TLSConfig struct {
	CertFile    string
	KeyFile     string
	SNI         string
	MinVersion  string
	CipherSuite string
}

func LoadProfile(name string) (*Profile, error) {
	profiles := map[string]*Profile{
		"teams": {
			Name:        "teams",
			Description: "Microsoft Teams mimicry",
			HTTPGet: HTTPGetConfig{
				Method: "GET",
				URI:    []string{"/api/v1/meetings", "/api/v1/chats", "/api/v1/calls"},
				Port:   []int{443},
				Headers: map[string]string{
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
					"Accept":     "application/json",
					"X-MS-Client": "TeamsDesktop",
				},
			},
			HTTPPost: HTTPPostConfig{
				Method: "POST",
				URI:    "/api/v1/messages",
				Port:   []int{443},
				Headers: map[string]string{
					"Content-Type": "application/json",
					"X-MS-Client":  "TeamsDesktop",
				},
			},
		},
		"office": {
			Name:        "office",
			Description: "Microsoft Office 365 mimicry",
			HTTPGet: HTTPGetConfig{
				Method: "GET",
				URI:    []string{"/api/v2/me", "/api/v2/drive/root"},
				Port:   []int{443},
				Headers: map[string]string{
					"User-Agent": "Microsoft Office/16.0",
					"Accept":     "application/json",
				},
			},
			HTTPPost: HTTPPostConfig{
				Method: "POST",
				URI:    "/api/v2/sendMail",
				Port:   []int{443},
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
		},
		"google": {
			Name:        "google",
			Description: "Google Workspace mimicry",
			HTTPGet: HTTPGetConfig{
				Method: "GET",
				URI:    []string{"/gmail/v1/messages", "/drive/v3/files"},
				Port:   []int{443},
				Headers: map[string]string{
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
					"Accept":     "application/json",
				},
			},
			HTTPPost: HTTPPostConfig{
				Method: "POST",
				URI:    "/gmail/v1/messages/send",
				Port:   []int{443},
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
		},
		"cloudflare": {
			Name:        "cloudflare",
			Description: "Cloudflare CDN mimicry",
			HTTPGet: HTTPGetConfig{
				Method: "GET",
				URI:    []string{"/cdn-cgi/trace", "/__down"},
				Port:   []int{443, 80},
				Headers: map[string]string{
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				},
			},
			HTTPPost: HTTPPostConfig{
				Method: "POST",
				URI:    "/cdn-cgi/submit",
				Port:   []int{443},
				Headers: map[string]string{
					"Content-Type": "application/octet-stream",
				},
			},
		},
	}

	profile, exists := profiles[name]
	if !exists {
		return nil, fmt.Errorf("profile not found: %s", name)
	}

	return profile, nil
}

func (p *Profile) GetHTTPRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest(p.HTTPGet.Method, url, nil)
	if err != nil {
		return nil, err
	}

	for key, value := range p.HTTPGet.Headers {
		req.Header.Set(key, value)
	}

	return req, nil
}

func (p *Profile) GetHTTPRequestWithJitter(url string) (*http.Request, error) {
	req, err := p.GetHTTPRequest(url)
	if err != nil {
		return nil, err
	}

	jitter := time.Duration(float64(time.Second) * p.HTTPGet.Jitter)
	time.Sleep(jitter)

	return req, nil
}

func (p *Profile) GetHTTPSConfig() (*TLSConfig, error) {
	return &p.TLS, nil
}
