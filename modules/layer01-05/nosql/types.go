package nosql

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type NoSQLDBType string

const (
	NoSQLDBMongoDB      NoSQLDBType = "mongodb"
	NoSQLDBElasticsearch NoSQLDBType = "elasticsearch"
	NoSQLDBCouchDB      NoSQLDBType = "couchdb"
	NoSQLDBRedis        NoSQLDBType = "redis"
	NoSQLDBCassandra    NoSQLDBType = "cassandra"
)

type InjectionTechnique string

const (
	TechniqueAuthBypass     InjectionTechnique = "auth_bypass"
	TechniqueBooleanBlind   InjectionTechnique = "boolean_blind"
	TechniqueTimeBased      InjectionTechnique = "time_based"
	TechniqueJSInject       InjectionTechnique = "js_inject"
	TechniqueLookupExfil    InjectionTechnique = "lookup_exfil"
	TechniqueQueryInject    InjectionTechnique = "query_inject"
	TechniqueAggregation    InjectionTechnique = "aggregation_exfil"
	TechniqueScriptInject   InjectionTechnique = "script_inject"
	TechniqueCommandInject  InjectionTechnique = "command_inject"
	TechniqueKeyDump        InjectionTechnique = "key_dump"
	TechniqueCQLInject      InjectionTechnique = "cql_inject"
)

type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

type NoSQLConfig struct {
	Target        string        `json:"target"`
	Port          int           `json:"port"`
	Timeout       time.Duration `json:"timeout"`
	MaxRetries    int           `json:"max_retries"`
	Username      string        `json:"username"`
	Password      string        `json:"password"`
	Database      string        `json:"database"`
	Collection    string        `json:"collection"`
	AuthDB        string        `json:"auth_db"`
	UserAgent     string        `json:"user_agent"`
	SSL           bool          `json:"ssl"`
	VerifySSL     bool          `json:"verify_ssl"`
	ProxyURL      string        `json:"proxy_url"`
	DBTypes       []NoSQLDBType `json:"db_types"`
	Techniques    []InjectionTechnique `json:"techniques"`
	Verbose       bool          `json:"verbose"`
}

func DefaultNoSQLConfig() *NoSQLConfig {
	return &NoSQLConfig{
		Port:       27017,
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		Database:   "test",
		Collection: "users",
		AuthDB:     "admin",
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		VerifySSL:  true,
		DBTypes: []NoSQLDBType{
			NoSQLDBMongoDB,
			NoSQLDBElasticsearch,
			NoSQLDBCouchDB,
			NoSQLDBRedis,
			NoSQLDBCassandra,
		},
		Techniques: []InjectionTechnique{
			TechniqueAuthBypass,
			TechniqueBooleanBlind,
			TechniqueTimeBased,
			TechniqueJSInject,
			TechniqueQueryInject,
		},
	}
}

type InjectionPoint struct {
	ID          string            `json:"id"`
	Target      string            `json:"target"`
	DBType      NoSQLDBType       `json:"db_type"`
	Technique   InjectionTechnique `json:"technique"`
	Field       string            `json:"field"`
	Payload     string            `json:"payload"`
	Parameters  map[string]string `json:"parameters"`
	Severity    Severity          `json:"severity"`
	Verified    bool              `json:"verified"`
	Timestamp   time.Time         `json:"timestamp"`
}

type ExploitResult struct {
	Success     bool              `json:"success"`
	Injection   *InjectionPoint   `json:"injection"`
	Data        map[string]interface{} `json:"data"`
	Credentials []CredentialEntry `json:"credentials"`
	CmdOutput   string            `json:"cmd_output"`
	Files       []FileEntry       `json:"files"`
	Error       string            `json:"error"`
	Timestamp   time.Time         `json:"timestamp"`
}

type CredentialEntry struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Database string `json:"database"`
	Role     string `json:"role"`
	Source   string `json:"source"`
}

type FileEntry struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Size    int64  `json:"size"`
}

type ScanResult struct {
	Target         string           `json:"target"`
	Ports          []PortResult     `json:"ports"`
	Injections     []InjectionPoint `json:"injections"`
	Vulnerable     bool             `json:"vulnerable"`
	DBType         NoSQLDBType      `json:"db_type"`
	Version        string           `json:"version"`
	Databases      []string         `json:"databases"`
	Collections    []string         `json:"collections"`
	Timestamp      time.Time        `json:"timestamp"`
}

type PortResult struct {
	Port     int    `json:"port"`
	Open     bool   `json:"open"`
	Service  string `json:"service"`
	Version  string `json:"version"`
}

type NoSQLScanResult struct {
	Success    bool              `json:"success"`
	DBType     NoSQLDBType       `json:"db_type"`
	Version    string            `json:"version"`
	Databases  []string          `json:"databases"`
	Collections []string         `json:"collections"`
	InjectionPoints []InjectionPoint `json:"injection_points"`
	Error      string            `json:"error"`
}

func (r *ScanResult) AddInjection(ip InjectionPoint) {
	r.Injections = append(r.Injections, ip)
	if ip.Severity >= SeverityHigh {
		r.Vulnerable = true
	}
}

func (r *ScanResult) Summary() string {
	summary := fmt.Sprintf("Target: %s, DB: %s, Vuln: %v, Injections: %d",
		r.Target, r.DBType, r.Vulnerable, len(r.Injections))
	if r.Version != "" {
		summary += fmt.Sprintf(", Version: %s", r.Version)
	}
	return summary
}

type HTTPClient struct {
	client *http.Client
	config *NoSQLConfig
}

func NewHTTPClient(config *NoSQLConfig) *HTTPClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.VerifySSL,
		},
	}

	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &HTTPClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		},
		config: config,
	}
}

func (h *HTTPClient) Get(target string, headers map[string]string) (*http.Response, []byte, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}

	h.setHeaders(req, headers)

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, fmt.Errorf("read response: %w", err)
	}

	return resp, body, nil
}

func (h *HTTPClient) Post(target string, body io.Reader, headers map[string]string) (*http.Response, []byte, error) {
	req, err := http.NewRequest("POST", target, body)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}

	h.setHeaders(req, headers)

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, fmt.Errorf("read response: %w", err)
	}

	return resp, respBody, nil
}

func (h *HTTPClient) Put(target string, body io.Reader, headers map[string]string) (*http.Response, []byte, error) {
	req, err := http.NewRequest("PUT", target, body)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}

	h.setHeaders(req, headers)

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, fmt.Errorf("read response: %w", err)
	}

	return resp, respBody, nil
}

func (h *HTTPClient) Delete(target string, headers map[string]string) (*http.Response, []byte, error) {
	req, err := http.NewRequest("DELETE", target, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}

	h.setHeaders(req, headers)

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, fmt.Errorf("read response: %w", err)
	}

	return resp, body, nil
}

func (h *HTTPClient) setHeaders(req *http.Request, headers map[string]string) {
	req.Header.Set("User-Agent", h.config.UserAgent)
	if h.config.Username != "" && h.config.Password != "" {
		req.SetBasicAuth(h.config.Username, h.config.Password)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

func BuildURL(target, path string, port int) string {
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}
	if port > 0 && port != 80 && port != 443 {
		target = strings.TrimSuffix(target, "/")
		if !strings.Contains(target[8:], ":") {
			target = fmt.Sprintf("%s:%d", target, port)
		}
	}
	return strings.TrimSuffix(target, "/") + path
}

func GenerateID() string {
	b := make([]byte, 8)
	for i := range b {
		b[i] = "0123456789abcdef"[time.Now().UnixNano()%16]
		time.Sleep(time.Nanosecond)
	}
	return string(b)
}
