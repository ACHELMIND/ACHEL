package ipv6

import "time"

type IPv6Config struct {
	Target       string        `json:"target"`
	Interface    string        `json:"interface"`
	SourceIP     string        `json:"source_ip"`
	PrefixLen    int           `json:"prefix_len"`
	Lifetime     time.Duration `json:"lifetime"`
	DNSServer    string        `json:"dns_server"`
	EnableRouter bool          `json:"enable_router"`
}

type IPv6Result struct {
	Success    bool          `json:"success"`
	Method     string        `json:"method"`
	Message    string        `json:"message"`
	Duration   time.Duration `json:"duration"`
	Packets    int           `json:"packets"`
	TargetsHit int           `json:"targets_hit"`
}

type NDPAttack struct {
	TargetMAC   string `json:"target_mac"`
	RouterMAC   string `json:"router_mac"`
	TargetIPv6  string `json:"target_ipv6"`
	GatewayIPv6 string `json:"gateway_ipv6"`
}

type DNSv6Attack struct {
	Domain    string `json:"domain"`
	FakeIPv6  string `json:"fake_ipv6"`
	OrigTTL   uint32 `json:"orig_ttl"`
	LowerTTL  uint32 `json:"lower_ttl"`
	SpoofType string `json:"spoof_type"`
}

type TransitionAbuse struct {
	Technique  string `json:"technique"`
	TunnelType string `json:"tunnel_type"`
	Endpoint   string `json:"endpoint"`
	Payload    []byte `json:"payload"`
}

type NDPState struct {
	Neighbors   map[string]string `json:"neighbors"`
	Router      string            `json:"router"`
	Prefix      string            `json:"prefix"`
	MACBindings map[string]string `json:"mac_bindings"`
}

type TunnelInfo struct {
	Type       string        `json:"type"`
	LocalAddr  string        `json:"local_addr"`
	RemoteAddr string        `json:"remote_addr"`
	MTU        int           `json:"mtu"`
	HopLimit   int           `json:"hop_limit"`
	Packets    int           `json:"packets"`
	Bytes      int64         `json:"bytes"`
	Uptime     time.Duration `json:"uptime"`
}
