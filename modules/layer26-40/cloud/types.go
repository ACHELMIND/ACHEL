package cloud

import "time"

type CloudProvider int

const (
	CloudProviderAWS CloudProvider = iota
	CloudProviderAzure
	CloudProviderGCP
	CloudProviderOCI
	CloudProviderDigitalOcean
)

func (c CloudProvider) String() string {
	return [...]string{"AWS", "Azure", "GCP", "OCI", "DigitalOcean"}[c]
}

type CloudConfig struct {
	Provider    CloudProvider
	AccessKey   string
	SecretKey   string
	SessionToken string
	Region      string
	ProjectID   string
	TenantID    string
	ClientID    string
	ClientSecret string
	Profile     string
	Endpoint    string
}

type CloudResult struct {
	ID          string        `json:"id"`
	Provider    CloudProvider `json:"provider"`
	AccountID   string        `json:"account_id"`
	IAMPolicies []IAMPolicy   `json:"iam_policies"`
	PrivPaths   []PrivescPath `json:"privilege_escalation_paths"`
	Lambdas     []LambdaInfo  `json:"lambdas"`
	Buckets     []BucketInfo  `json:"buckets"`
	Instances   []InstanceInfo `json:"instances"`
	Secrets     []SecretEntry `json:"secrets"`
	Timestamp   time.Time     `json:"timestamp"`
}

type IAMPolicy struct {
	Name       string   `json:"name"`
	ARN        string   `json:"arn"`
	Effect     string   `json:"effect"`
	Actions    []string `json:"actions"`
	Resources  []string `json:"resources"`
	Condition  string   `json:"condition,omitempty"`
}

type IAMConfig struct {
	RoleEnum      bool
	UserEnum      bool
	PolicyAnalysis bool
	PrivescDetect bool
	ServiceEnum   []string
}

type PrivescPath struct {
	From      string   `json:"from"`
	To        string   `json:"to"`
	Method    string   `json:"method"`
	Risk      string   `json:"risk"`
	Actions   []string `json:"actions"`
}

type LambdaConfig struct {
	FunctionName string
	Runtime      string
	Handler      string
	Role         string
	Code         string
	Environment  map[string]string
}

type LambdaInfo struct {
	Name      string            `json:"name"`
	ARN       string            `json:"arn"`
	Runtime   string            `json:"runtime"`
	Role      string            `json:"role"`
	EnvVars   map[string]string `json:"env_vars"`
	Memory    int               `json:"memory"`
	Timeout   int               `json:"timeout"`
	ManagedPolicies []string    `json:"managed_policies"`
}

type BucketInfo struct {
	Name      string   `json:"name"`
	Region    string   `json:"region"`
	Public    bool     `json:"public"`
	Encrypted bool     `json:"encrypted"`
	Policies  []string `json:"policies"`
}

type InstanceInfo struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	State     string            `json:"state"`
	Type      string            `json:"type"`
	PublicIP  string            `json:"public_ip"`
	IAMRole   string            `json:"iam_role"`
	Metadata  map[string]string `json:"metadata"`
}

type SecretEntry struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Source   string `json:"source"`
	Severity string `json:"severity"`
}

type AzureADConfig struct {
	TenantID       string
	ClientID       string
	ClientSecret   string
	SubscriptionID string
}

type GCPConfig struct {
	ProjectID  string
	ServiceAcc string
	KeyFile    string
	Zone       string
}
