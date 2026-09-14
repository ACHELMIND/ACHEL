package osint

import (
	"time"
)

type OSINTConfig struct {
	Target        string            `json:"target"`
	Timeout       time.Duration     `json:"timeout"`
	MaxConcurrency int              `json:"max_concurrency"`
	Ports         []int             `json:"ports"`
	Wordlist      []string          `json:"wordlist"`
	APIKeys       map[string]string `json:"api_keys"`
	ProxyURL      string            `json:"proxy_url"`
	FollowRedirects bool           `json:"follow_redirects"`
	Verbose       bool              `json:"verbose"`
}

func DefaultOSINTConfig() *OSINTConfig {
	return &OSINTConfig{
		Timeout:         30 * time.Second,
		MaxConcurrency:  10,
		Ports:           commonPorts(),
		FollowRedirects: true,
		Verbose:         false,
	}
}

func commonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
		993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
		8080, 8443, 8888, 9200, 9300, 27017,
	}
}

type ReconResult struct {
	Target    string         `json:"target"`
	DNS       *DNSResult     `json:"dns,omitempty"`
	Ports     []OpenPort     `json:"ports,omitempty"`
	Services  []ServiceInfo  `json:"services,omitempty"`
	Web       *WebResult     `json:"web,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

type FullReconResult struct {
	Target    string         `json:"target"`
	DNS       *DNSResult     `json:"dns,omitempty"`
	Ports     []OpenPort     `json:"ports,omitempty"`
	Services  []ServiceInfo  `json:"services,omitempty"`
	Web       *WebResult     `json:"web,omitempty"`
	Person    *PersonResult  `json:"person,omitempty"`
	Cloud     *CloudResult   `json:"cloud,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

type DNSResult struct {
	Domain      string   `json:"domain"`
	Subdomains  []string `json:"subdomains"`
	MXRecords   []string `json:"mx_records"`
	NSRecords   []string `json:"ns_records"`
	ARecords    []string `json:"a_records"`
	AAAARecords []string `json:"aaaa_records"`
	TXTRecords  []string `json:"txt_records"`
}

type OpenPort struct {
	Port     int    `json:"port"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version"`
	Banner   string `json:"banner,omitempty"`
}

type ServiceInfo struct {
	Port     int    `json:"port"`
	Service  string `json:"service"`
	Version  string `json:"version"`
	Product  string `json:"product"`
	OS       string `json:"os"`
	Extra    string `json:"extra,omitempty"`
}

type WebResult struct {
	URL       string            `json:"url"`
	TechStack *TechStack        `json:"tech_stack,omitempty"`
	WAF       *WAFInfo          `json:"waf,omitempty"`
	Cert      *CertInfo         `json:"cert,omitempty"`
	Robots    []string          `json:"robots,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
}

type TechStack struct {
	Languages  []string          `json:"languages"`
	Frameworks []string          `json:"frameworks"`
	CMS        string            `json:"cms,omitempty"`
	Server     string            `json:"server,omitempty"`
	Analytics  []string          `json:"analytics,omitempty"`
	JS         []string          `json:"js_libraries,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`
}

type WAFInfo struct {
	Detected bool   `json:"detected"`
	Name     string `json:"name,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Version  string `json:"version,omitempty"`
	RuleSet  string `json:"ruleset,omitempty"`
}

type CertInfo struct {
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DNSNames  []string  `json:"dns_names"`
	Serial    string    `json:"serial"`
	KeySize   int       `json:"key_size"`
	SelfSigned bool     `json:"self_signed"`
}

type PersonResult struct {
	Emails    []string        `json:"emails"`
	Social    *SocialProfile  `json:"social,omitempty"`
	Repos     []GitRepo       `json:"repos,omitempty"`
}

type SocialProfile struct {
	Username   string            `json:"username"`
	Platform   string            `json:"platform"`
	Bio        string            `json:"bio,omitempty"`
	Followers  int               `json:"followers"`
	Following  int               `json:"following"`
	Repos      int               `json:"repos"`
	URLs       []string          `json:"urls,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type GitRepo struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Description string    `json:"description,omitempty"`
	Language    string    `json:"language,omitempty"`
	Stars       int       `json:"stars"`
	Forks       int       `json:"forks"`
	IsPrivate   bool      `json:"is_private"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CloudResult struct {
	AWS   *AWSResult   `json:"aws,omitempty"`
	Azure *AzureResult `json:"azure,omitempty"`
	GCP   *GCPResult   `json:"gcp,omitempty"`
}

type BucketInfo struct {
	Name      string    `json:"name"`
	Region    string    `json:"region"`
	Visible   bool      `json:"visible"`
	Public    bool      `json:"public"`
	Size      int64     `json:"size"`
	Modified  time.Time `json:"modified"`
}

type AWSResult struct {
	Buckets []BucketInfo `json:"buckets"`
}

type BlobInfo struct {
	Name      string    `json:"name"`
	Container string    `json:"container"`
	Size      int64     `json:"size"`
	Modified  time.Time `json:"modified"`
	Public    bool      `json:"public"`
}

type AzureResult struct {
	Blobs []BlobInfo `json:"blobs"`
}

type GCPResult struct {
	Buckets []BucketInfo `json:"buckets"`
}
