package certforgery

import "time"

type CertForgeConfig struct {
	Domain     string        `json:"domain"`
	CA         string        `json:"ca"`
	KeyType    string        `json:"key_type"`
	KeySize    int           `json:"key_size"`
	ValidDays  int           `json:"valid_days"`
	Timeout    time.Duration `json:"timeout"`
}

type CertResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	CertPEM  string        `json:"cert_pem"`
	KeyPEM   string        `json:"key_pem"`
	Risk     string        `json:"risk"`
}

type CertType struct {
	Name      string `json:"name"`
	CA        string `json:"ca"`
	Trust     string `json:"trust"`
	ValidDays int    `json:"valid_days"`
}

type ForgeMethod struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	TrustLevel  string `json:"trust_level"`
}

type CertificateInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	Serial     string    `json:"serial"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	KeyUsage   []string  `json:"key_usage"`
	ExtKeyUsage []string `json:"ext_key_usage"`
	DNSNames   []string  `json:"dns_names"`
	IPAddresses []string `json:"ip_addresses"`
}

type TransparencyLog struct {
	Name    string    `json:"name"`
	URL     string    `json:"url"`
	Entries []CTEntry `json:"entries"`
}

type CTEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Domain      string    `json:"domain"`
	Issuer      string    `json:"issuer"`
	SerialNumber string  `json:"serial_number"`
}

type CAInfo struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	RootCerts []string `json:"root_certs"`
	Trusted   bool     `json:"trusted"`
}

type TrustedCAExploit struct {
	CA         string `json:"ca"`
	Technique  string `json:"technique"`
	IssuerCN  string `json:"issuer_cn"`
	SerialNum string `json:"serial_num"`
}
