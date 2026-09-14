package infra

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"text/template"

	"github.com/angel-platform/angel/pkg/logger"
)

type NginxRedirector struct {
	config *RedirectorConfig
	log    *logger.Logger
	mu     sync.RWMutex
}

func NewNginxRedirector(config *RedirectorConfig) *NginxRedirector {
	if config == nil {
		config = DefaultRedirectorConfig()
	}
	return &NginxRedirector{
		config: config,
		log:    logger.New("nginx-redirector", logger.LevelInfo),
	}
}

func (n *NginxRedirector) ConfigureRedirector(config *RedirectorConfig) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	n.config = config
	n.log.Info("Redirector configured: %s:%d", config.ListenAddr, config.ListenPort)
	return nil
}

func (n *NginxRedirector) AddRoute(path, backend string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	if backend == "" {
		return fmt.Errorf("backend cannot be empty")
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	n.config.Routes[path] = backend
	n.log.Info("Route added: %s -> %s", path, backend)
	return nil
}

func (n *NginxRedirector) RemoveRoute(path string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	if _, ok := n.config.Routes[path]; !ok {
		return fmt.Errorf("route not found: %s", path)
	}

	delete(n.config.Routes, path)
	n.log.Info("Route removed: %s", path)
	return nil
}

var nginxTemplate = `# Auto-generated Nginx configuration
# Redirector configuration

worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    gzip on;

{{- if .RateLimit}}
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=ratelimit:10m rate={{.RateLimit}}r/s;
{{- end}}

{{- if .SSL}}
    # SSL configuration
    server {
        listen {{.ListenPort}} ssl http2;
        server_name _;

        ssl_certificate {{.SSLCert}};
        ssl_certificate_key {{.SSLKey}};
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
{{- else}}
    server {
        listen {{.ListenPort}};
        server_name _;
{{- end}}

{{- range $path, $backend := .Routes}}
        # Route: {{ $path }} -> {{ $backend }}
        location {{ $path }} {
            proxy_pass {{ $backend }};
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout {{$.UpstreamTimeout}};
            proxy_read_timeout {{$.UpstreamTimeout}};
{{- if $.RateLimit}}
            limit_req zone=ratelimit burst=20 nodelay;
{{- end}}
{{- range $key, $val := $.Headers}}
            add_header {{ $key }} "{{ $val }}";
{{- end}}
        }
{{- end}}

        # Default catch-all
        location / {
            return 404;
        }
    }
}
`

type nginxData struct {
	ListenAddr      string
	ListenPort      int
	Routes          map[string]string
	SSL             bool
	SSLCert         string
	SSLKey          string
	UpstreamTimeout string
	RateLimit       int
	Headers         map[string]string
}

func (n *NginxRedirector) GenerateConfig() string {
	n.mu.RLock()
	defer n.mu.RUnlock()

	data := nginxData{
		ListenAddr:      n.config.ListenAddr,
		ListenPort:      n.config.ListenPort,
		Routes:          n.config.Routes,
		SSL:             n.config.SSL,
		SSLCert:         n.config.SSLCert,
		SSLKey:          n.config.SSLKey,
		UpstreamTimeout: fmt.Sprintf("%ds", int(n.config.UpstreamTimeout.Seconds())),
		RateLimit:       n.config.RateLimit,
		Headers:         n.config.Headers,
	}

	tmpl, err := template.New("nginx").Parse(nginxTemplate)
	if err != nil {
		n.log.Error("Failed to parse nginx template: %v", err)
		return "# error generating config"
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		n.log.Error("Failed to execute nginx template: %v", err)
		return "# error generating config"
	}

	return buf.String()
}
