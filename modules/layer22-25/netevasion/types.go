package netevasion

import (
	"net"
	"time"
)

type EvasionMethod string

const (
	MethodIPRotation      EvasionMethod = "ip_rotation"
	MethodTrafficMorph    EvasionMethod = "traffic_morph"
	MethodPacketObfusc    EvasionMethod = "packet_obfusc"
	MethodDomainFronting  EvasionMethod = "domain_fronting"
)

type EvasionResult struct {
	Success   bool            `json:"success"`
	Method    EvasionMethod   `json:"method"`
	Details   string          `json:"details"`
	Error     string          `json:"error,omitempty"`
	Duration  time.Duration   `json:"duration"`
	Timestamp time.Time       `json:"timestamp"`
}

type NetEvasionConfig struct {
	ProxyList        []string          `json:"proxy_list"`
	Timeout          time.Duration     `json:"timeout"`
	JitterPercent    float64           `json:"jitter_percent"`
	Methods          []EvasionMethod   `json:"methods"`
	TargetCDN        string            `json:"target_cdn,omitempty"`
	EncKey           []byte            `json:"enc_key,omitempty"`
	Verbose          bool              `json:"verbose"`
}

func DefaultNetEvasionConfig() *NetEvasionConfig {
	return &NetEvasionConfig{
		Timeout:       30 * time.Second,
		JitterPercent: 0.25,
		Methods:       AllEvasionMethods(),
		Verbose:       false,
	}
}

func AllEvasionMethods() []EvasionMethod {
	return []EvasionMethod{
		MethodIPRotation,
		MethodTrafficMorph,
		MethodPacketObfusc,
		MethodDomainFronting,
	}
}

type ProxyInfo struct {
	Address    string        `json:"address"`
	Protocol   string        `json:"protocol"`
	Alive      bool          `json:"alive"`
	Latency    time.Duration `json:"latency"`
	LastCheck  time.Time     `json:"last_check"`
	FailCount  int           `json:"fail_count"`
}

type IPRotationResult struct {
	CurrentIP  string      `json:"current_ip"`
	PreviousIP string      `json:"previous_ip"`
	Proxy      *ProxyInfo  `json:"proxy"`
	TotalAvail int         `json:"total_available"`
	Error      string      `json:"error,omitempty"`
}

type TrafficMorphConfig struct {
	TLSFingerprint  string        `json:"tls_fingerprint"`
	HTTP2Priority   string        `json:"http2_priority"`
	SleepJitter     float64       `json:"sleep_jitter"`
	JitterRange     time.Duration `json:"jitter_range"`
}

type PacketObfuscConfig struct {
	EncryptKey  []byte `json:"encrypt_key"`
	Encoding    string `json:"encoding"`
	Protocol    string `json:"protocol"`
}

type DomainFrontConfig struct {
	Target    string `json:"target"`
	CDN       string `json:"cdn"`
	Host      string `json:"host"`
	Protocol  string `json:"protocol"`
}

type DomainFrontResult struct {
	Success   bool         `json:"success"`
	Request   *net.TCPAddr `json:"-"`
	RequestStr string      `json:"request"`
	Error     string      `json:"error,omitempty"`
}
