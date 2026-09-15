package grpc

type GRPCService struct {
	Name     string       `json:"name"`
	Methods  []GRPCMethod `json:"methods"`
	Package  string       `json:"package"`
	Version  string       `json:"version"`
}

type GRPCMethod struct {
	Name       string   `json:"name"`
	InputType  string   `json:"input_type"`
	OutputType string   `json:"output_type"`
	Streaming  bool     `json:"streaming"`
	Auth       string   `json:"auth"`
}

type ReflectionResult struct {
	Services      []GRPCService `json:"services"`
	TotalMethods  int           `json:"total_methods"`
	AuthService   string        `json:"auth_service"`
	ServerVersion string        `json:"server_version"`
}

type GRPCConfig struct {
	TargetHost string            `json:"target_host"`
	TargetPort int               `json:"target_port"`
	TLS        bool              `json:"tls"`
	Headers    map[string]string `json:"headers"`
	Reflection bool              `json:"reflection"`
	ServiceName string           `json:"service_name"`
	MethodName  string           `json:"method_name"`
}

type GRPCResult struct {
	Reflection   *ReflectionResult `json:"reflection,omitempty"`
	Enumerated   bool              `json:"enumerated"`
	AuthBypass   bool              `json:"auth_bypass"`
	ProtoLeak    bool              `json:"proto_leak"`
	Details      string            `json:"details"`
	Services     []GRPCService     `json:"services"`
	RiskScore    float64           `json:"risk_score"`
}

type ProtoFile struct {
	Name     string       `json:"name"`
	Messages []string     `json:"messages"`
	Services []GRPCService `json:"services"`
}
