package dbpost

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DBMS string

const (
	DBMSOracle   DBMS = "oracle"
	DBMSMySQL    DBMS = "mysql"
	DBMSPostgres DBMS = "postgresql"
	DBMSMSSQL    DBMS = "mssql"
)

type ExploitTechnique string

const (
	TechniqueJavaObject     ExploitTechnique = "java_object_inject"
	TechniqueKhuntCmd       ExploitTechnique = "khunt_cmd"
	TechniqueKhuntHash      ExploitTechnique = "khunt_hash"
	TechniqueRegistryDump   ExploitTechnique = "registry_dump"
	TechniqueUDFInstall     ExploitTechnique = "udf_install"
	TechniqueUserExtract    ExploitTechnique = "user_extract"
	TechniqueFSAccess       ExploitTechnique = "fs_access"
	TechniqueCopyProgram    ExploitTechnique = "copy_program"
	TechniquePGShadow       ExploitTechnique = "pg_shadow"
	TechniqueXPCmdShell     ExploitTechnique = "xp_cmdshell"
	TechniqueCLRAssembly    ExploitTechnique = "clr_assembly"
	TechniqueSQLLogins      ExploitTechnique = "sql_logins"
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

type DBPostConfig struct {
	Target      string        `json:"target"`
	Port        int           `json:"port"`
	Timeout     time.Duration `json:"timeout"`
	MaxRetries  int           `json:"max_retries"`
	Username    string        `json:"username"`
	Password    string        `json:"password"`
	Database    string        `json:"database"`
	Instance    string        `json:"instance"`
	ServiceName string        `json:"service_name"`
	SID         string        `json:"sid"`
	SSL         bool          `json:"ssl"`
	VerifySSL   bool          `json:"verify_ssl"`
	ProxyURL    string        `json:"proxy_url"`
	UserAgent   string        `json:"user_agent"`
	Verbose     bool          `json:"verbose"`
}

func DefaultDBPostConfig() *DBPostConfig {
	return &DBPostConfig{
		Port:        1521,
		Timeout:     30 * time.Second,
		MaxRetries:  3,
		Database:    "test",
		ServiceName: "ORCL",
		SID:         "ORCL",
		VerifySSL:   true,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
}

type DBCreds struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Database    string `json:"database"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Instance    string `json:"instance"`
	ServiceName string `json:"service_name"`
	SID         string `json:"sid"`
	IsAdmin     bool   `json:"is_admin"`
	Role        string `json:"role"`
}

type PostExploitResult struct {
	Success       bool                 `json:"success"`
	DBMS          DBMS                 `json:"dbms"`
	Technique     ExploitTechnique     `json:"technique"`
	Credentials   []CredentialEntry    `json:"credentials"`
	CmdOutput     string               `json:"cmd_output"`
	Files         []FileEntry          `json:"files"`
	Data          map[string]interface{} `json:"data"`
	Error         string               `json:"error"`
	Timestamp     time.Time            `json:"timestamp"`
}

type CredentialEntry struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Database string `json:"database"`
	Role     string `json:"role"`
	Source   string `json:"source"`
	IsAdmin  bool   `json:"is_admin"`
}

type FileEntry struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Size    int64  `json:"size"`
}

type ExploitResult struct {
	Success     bool                 `json:"success"`
	Technique   ExploitTechnique     `json:"technique"`
	Credentials []CredentialEntry    `json:"credentials"`
	CmdOutput   string               `json:"cmd_output"`
	Files       []FileEntry          `json:"files"`
	Data        map[string]interface{} `json:"data"`
	Error       string               `json:"error"`
	Timestamp   time.Time            `json:"timestamp"`
}

type HTTPClient struct {
	client *http.Client
	config *DBPostConfig
}

func NewHTTPClient(config *DBPostConfig) *HTTPClient {
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
