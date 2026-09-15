package container

import "time"

type ContainerType int

const (
	ContainerTypeDocker ContainerType = iota
	ContainerTypePodman
	ContainerTypeContainerd
	ContainerTypeCRIO
	ContainerTypeLXC
	ContainerTypeLXD
)

func (c ContainerType) String() string {
	return [...]string{"Docker", "Podman", "containerd", "CRI-O", "LXC", "LXD"}[c]

}

type EscapeMethod int

const (
	EscapeMethodSocketMount EscapeMethod = iota
	EscapeMethodPrivilegedContainer
	EscapeMethodPIDNamespace
	EscapeMethodCgroupEscape
	EscapeMethodKernelExploit
	EscapeMethodContainerdShim
	EscapeMethodProcfsEscape
	EscapeMethodSysrqEscape
)

func (e EscapeMethod) String() string {
	return [...]string{
		"SocketMount", "PrivilegedContainer", "PIDNamespace",
		"CgroupEscape", "KernelExploit", "ContainerdShim",
		"ProcfsEscape", "SysrqEscape",
	}[e]
}

type ContainerEscapeConfig struct {
	ContainerType   ContainerType
	EscapeMethods   []EscapeMethod
	TargetPath      string
	DockerSocket    string
	Kubeconfig      string
	Timeout         time.Duration
	Verbose         bool
}

type KubernetesConfig struct {
	APIServer       string
	Token           string
	CACert          string
	Namespace       string
	ServiceAccount  string
	RBACEnum        bool
	PodEscape       bool
	NodeEnum        bool
	WorkerNodes     []string
}

type ContainerResult struct {
	ID              string          `json:"id"`
	ContainerName   string          `json:"container_name"`
	ContainerType   ContainerType  `json:"container_type"`
	EscapeMethod    EscapeMethod   `json:"escape_method"`
	Success         bool           `json:"success"`
	Details         string         `json:"details"`
	Vulns           []string       `json:"vulns"`
	SecretsFound    []SecretEntry  `json:"secrets_found"`
	ContainerInfo   ContainerInfo  `json:"container_info"`
	Timestamp       time.Time      `json:"timestamp"`
}

type SecretEntry struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Source   string `json:"source"`
	Severity string `json:"severity"`
}

type ContainerInfo struct {
	Image       string            `json:"image"`
	Labels      map[string]string `json:"labels"`
	Env         []string          `json:"env"`
	Mounts      []string          `json:"mounts"`
	Ports       []string          `json:"ports"`
	Privileged  bool              `json:"privileged"`
	PID         int               `json:"pid"`
	NetworkMode string            `json:"network_mode"`
}

type KubernetesResult struct {
	ID            string            `json:"id"`
	APIServer     string            `json:"api_server"`
	Namespaces    []NamespaceInfo   `json:"namespaces"`
	Services      []ServiceInfo     `json:"services"`
	Secrets       []SecretEntry     `json:"secrets"`
	Pods          []PodInfo         `json:"pods"`
	Roles         []RoleInfo        `json:"roles"`
	Nodes         []NodeInfo        `json:"nodes"`
	EscapePaths   []string          `json:"escape_paths"`
	Timestamp     time.Time         `json:"timestamp"`
}

type NamespaceInfo struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	Status string            `json:"status"`
}

type ServiceInfo struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Type      string   `json:"type"`
	ClusterIP string   `json:"cluster_ip"`
	Ports     []string `json:"ports"`
}

type PodInfo struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	Node       string `json:"node"`
	Status     string `json:"status"`
	ServiceAcc string `json:"service_account"`
}

type RoleInfo struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Rules     []string `json:"rules"`
}

type NodeInfo struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Roles    []string `json:"roles"`
	InternalIP string `json:"internal_ip"`
}
