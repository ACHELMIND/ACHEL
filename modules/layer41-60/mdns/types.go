package mdns

import "time"

type MDNSConfig struct {
	Interface  string        `json:"interface"`
	ListenAddr string        `json:"listen_addr"`
	Domain     string        `json:"domain"`
	SpoofName  string        `json:"spoof_name"`
	SpoofIP    string        `json:"spoof_ip"`
	Timeout    time.Duration `json:"timeout"`
}

type MDNSResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Packets  int           `json:"packets"`
	Entries  int           `json:"entries"`
}

type PoisonMethod struct {
	Name        string `json:"name"`
	ServiceType string `json:"service_type"`
	Answers     int    `json:"answers"`
	Authority   bool   `json:"authority"`
}

type WPADConfig struct {
	DHCPServer string `json:"dhcp_server"`
	WPADDomain string `json:"wpad_domain"`
	PACURL     string `json:"pac_url"`
	ProxyAuto  string `json:"proxy_auto"`
}

type MDNSRecord struct {
	Name    string        `json:"name"`
	Type    uint16        `json:"type"`
	Class   uint16        `json:"class"`
	TTL     uint32        `json:"ttl"`
	Data    []byte        `json:"data"`
	Created time.Time     `json:"created"`
}

type ServiceEntry struct {
	Name       string            `json:"name"`
	Service    string            `json:"service"`
	Domain     string            `json:"domain"`
	Port       int               `json:"port"`
	IPv4       string            `json:"ipv4"`
	IPv6       string            `json:"ipv6"`
	Attributes map[string]string `json:"attributes"`
}

type LLMNRQuery struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class"`
}

type NBTNSName struct {
	Name     string `json:"name"`
	Suffix   string `json:"suffix"`
	Type     byte   `json:"type"`
}

type PoisonResult struct {
	Hostname  string `json:"hostname"`
	IP        string `json:"ip"`
	Service   string `json:"service"`
	Captured  bool   `json:"captured"`
	HashCount int    `json:"hash_count"`
}
