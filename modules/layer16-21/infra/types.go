package infra

import (
	"time"
)

type CloudProvider string

const (
	ProviderAWS   CloudProvider = "aws"
	ProviderGCP   CloudProvider = "gcp"
	ProviderAzure CloudProvider = "azure"
	ProviderDO    CloudProvider = "digitalocean"
	ProviderLinode CloudProvider = "linode"
)

type InfraConfig struct {
	Provider      CloudProvider      `json:"provider"`
	Region        string             `json:"region"`
	SSHKeyPath    string             `json:"ssh_key_path"`
	SubnetID      string             `json:"subnet_id"`
	VPCID         string             `json:"vpc_id"`
	SecurityGroup string             `json:"security_group"`
	Metadata      map[string]string  `json:"metadata"`
}

func DefaultInfraConfig() *InfraConfig {
	return &InfraConfig{
		Provider: ProviderAWS,
		Region:   "us-east-1",
		Metadata: make(map[string]string),
	}
}

type VPSInstance struct {
	ID         string            `json:"id"`
	Provider   CloudProvider     `json:"provider"`
	Region     string            `json:"region"`
	PublicIP   string            `json:"public_ip"`
	PrivateIP  string            `json:"private_ip"`
	Hostname   string            `json:"hostname"`
	Status     string            `json:"status"`
	OS         string            `json:"os"`
	SSHKey     string            `json:"ssh_key"`
	CreatedAt  time.Time         `json:"created_at"`
	Metadata   map[string]string `json:"metadata"`
}

type TFPlan struct {
	Changes  []TFChange `json:"changes"`
	Add      int        `json:"add"`
	Change   int        `json:"change"`
	Destroy  int        `json:"destroy"`
	Errored  bool       `json:"errored"`
	Raw      string     `json:"raw"`
}

type TFChange struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
}

type TFProvider string

const (
	TFProviderAWS       TFProvider = "aws"
	TFProviderGCP       TFProvider = "gcp"
	TFProviderAzure     TFProvider = "azure"
	TFProviderDigitalOcean TFProvider = "digitalocean"
)

type AnsibleRole string

const (
	AnsibleRoleRecon     AnsibleRole = "recon"
	AnsibleRolePhishing  AnsibleRole = "phishing"
	AnsibleRoleC2        AnsibleRole = "c2"
	AnsibleRoleDNS       AnsibleRole = "dns"
	AnsibleRoleWireGuard AnsibleRole = "wireguard"
	AnsibleRoleNginx     AnsibleRole = "nginx"
	AnsibleRoleFirewall  AnsibleRole = "firewall"
)

type RedirectorConfig struct {
	ListenAddr  string            `json:"listen_addr"`
	ListenPort  int               `json:"listen_port"`
	Routes      map[string]string `json:"routes"`
	SSL         bool              `json:"ssl"`
	SSLCert     string            `json:"ssl_cert"`
	SSLKey      string            `json:"ssl_key"`
	UpstreamTimeout time.Duration `json:"upstream_timeout"`
	RateLimit   int               `json:"rate_limit"`
	Headers     map[string]string `json:"headers"`
}

func DefaultRedirectorConfig() *RedirectorConfig {
	return &RedirectorConfig{
		ListenAddr:      "0.0.0.0",
		ListenPort:      443,
		Routes:          make(map[string]string),
		SSL:             true,
		UpstreamTimeout: 30 * time.Second,
		RateLimit:       100,
		Headers:         make(map[string]string),
	}
}

type VPNConfig struct {
	Type     string `json:"type"`
	ServerIP string `json:"server_ip"`
	PeerIP   string `json:"peer_ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	MTU      int    `json:"mtu"`
}

type IPRotation struct {
	Proxies     []string `json:"proxies"`
	CurrentIdx  int      `json:"current_idx"`
	MaxRetries  int      `json:"max_retries"`
	Timeout     time.Duration `json:"timeout"`
}

type WireGuardConfig struct {
	Interface  string `json:"interface"`
	PrivateKey string `json:"private_key"`
	Address    string `json:"address"`
	ListenPort int    `json:"listen_port"`
	PeerPubKey string `json:"peer_pub_key"`
	PeerAddr   string `json:"peer_addr"`
	PeerAllowed string `json:"peer_allowed"`
}

type OpenVPNConfig struct {
	Remote     string `json:"remote"`
	Port       int    `json:"port"`
	Proto      string `json:"proto"`
	Dev        string `json:"dev"`
	Cipher     string `json:"cipher"`
	Auth       string `json:"auth"`
	CertPath   string `json:"cert_path"`
	KeyPath    string `json:"key_path"`
	CAPath     string `json:"ca_path"`
	CompLZO    bool   `json:"comp_lzo"`
	PersistKey bool   `json:"persist_key"`
}
