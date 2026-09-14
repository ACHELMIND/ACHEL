package lateral

import (
	"time"
)

type LateralMethod string

const (
	MethodPsExec       LateralMethod = "psexec"
	MethodSMBExec      LateralMethod = "smbexec"
	MethodAtExec       LateralMethod = "atexec"
	MethodWmiExec      LateralMethod = "wmiexec"
	MethodDCOMExec     LateralMethod = "dcomexec"
	MethodServiceExec  LateralMethod = "serviceexec"
	MethodNamedPipe    LateralMethod = "namedpipe"
	MethodPassTheHash  LateralMethod = "pth"
	MethodWinRM        LateralMethod = "winrm"
	MethodRDP          LateralMethod = "rdp"
	MethodSSH          LateralMethod = "ssh"
	MethodPSRemoting   LateralMethod = "psremoting"
)

type AuthType string

const (
	AuthPassword  AuthType = "password"
	AuthHash      AuthType = "hash"
	AuthTicket    AuthType = "ticket"
	AuthKey       AuthType = "key"
	AuthToken     AuthType = "token"
)

type Protocol string

const (
	ProtoSMB    Protocol = "smb"
	ProtoWinRM  Protocol = "winrm"
	ProtoRDP    Protocol = "rdp"
	ProtoSSH    Protocol = "ssh"
	ProtoWMI    Protocol = "wmi"
	ProtoDCOM   Protocol = "dcom"
	ProtoTCP    Protocol = "tcp"
	ProtoUDP    Protocol = "udp"
)

type LateralConfig struct {
	DefaultMethod  LateralMethod
	Timeout        time.Duration
	MaxRetries     int
	ProxyEnabled   bool
	ProxyAddr      string
	SMBPort        int
	WinRMPort      int
	RDPPort        int
	SSHPort        int
	KDCPort        int
	Encrypt        bool
}

func DefaultLateralConfig() *LateralConfig {
	return &LateralConfig{
		DefaultMethod: MethodPsExec,
		Timeout:       30 * time.Second,
		MaxRetries:    3,
		ProxyEnabled:  false,
		SMBPort:       445,
		WinRMPort:     5985,
		RDPPort:       3389,
		SSHPort:       22,
		KDCPort:       88,
		Encrypt:       true,
	}
}

type Target struct {
	Host       string
	IP         string
	Port       int
	Protocol   Protocol
	OS         string
	Domain     string
	Hostname   string
	IsDC       bool
	IsAdmin    bool
	Reachable  bool
	Services   []string
	Metadata   map[string]string
}

type Credentials struct {
	Username   string
	Password   string
	Hash       string
	Domain     string
	AuthType   AuthType
	Ticket     []byte
	SSHKey     []byte
	Token      string
	Realm      string
}

type LateralResult struct {
	Success     bool
	Method      LateralMethod
	Target      *Target
	Output      string
	Error       string
	Duration    time.Duration
	Timestamp   time.Time
	SessionID   string
	Protocol    Protocol
	Elevated    bool
	ShellHandle interface{}
}

type LateralMethodImpl interface {
	Name() string
	Execute(target *Target, creds *Credentials) (*LateralResult, error)
	CanExecute(target *Target, creds *Credentials) bool
	RequiresElevation() bool
}

type SOCKS5Proxy struct {
	ListenAddr string
	ListenPort int
	Target     string
	TargetPort int
	Username   string
	Password   string
	Active     bool
}

type PortForward struct {
	ListenAddr string
	ListenPort int
	TargetAddr string
	TargetPort int
	Protocol   Protocol
	Active     bool
}

type TCPTunnel struct {
	ListenAddr string
	ListenPort int
	RemoteAddr string
	RemotePort int
	Encrypted  bool
	Key        []byte
	Active     bool
}

type DNSTunnel struct {
	Domain     string
	ListenAddr string
	ListenPort int
	RecordType string
	Active     bool
}

type ICMPTunnel struct {
	ListenAddr string
	TargetAddr string
	Interval   time.Duration
	Active     bool
}

type PivotConfig struct {
	Type        string
	ListenAddr  string
	ListenPort  int
	TargetAddr  string
	TargetPort  int
	Reconnect   bool
	MaxRetries  int
	KeepAlive   time.Duration
}

type ServiceInfo struct {
	Name        string
	DisplayName string
	Status      string
	StartType   string
	Path        string
	Account     string
}

type ProcessInfo struct {
	PID        int
	Name       string
	Path       string
	Arguments  string
	User       string
	SessionID  int
}

type ShareInfo struct {
	Name        string
	Path        string
	Type        string
	Remark      string
	Permissions string
}
