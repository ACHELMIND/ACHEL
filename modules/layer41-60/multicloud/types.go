package multicloud

import "time"

type MultiCloudConfig struct {
	SourceCloud string        `json:"source_cloud"`
	TargetCloud string        `json:"target_cloud"`
	Credentials CloudCredentials `json:"credentials"`
	Timeout     time.Duration `json:"timeout"`
}

type CloudCredentials struct {
	AWSAccessKey   string `json:"aws_access_key"`
	AWSSecretKey   string `json:"aws_secret_key"`
	AzureTenantID  string `json:"azure_tenant_id"`
	AzureClientID  string `json:"azure_client_id"`
	AzureSecret    string `json:"azure_secret"`
	GCPProjectID   string `json:"gcp_project_id"`
	GCPSAKeyPath   string `json:"gcp_sa_key_path"`
}

type MultiCloudResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Pivot    string        `json:"pivot"`
	Risk     string        `json:"risk"`
}

type CloudPivot struct {
	Source       string `json:"source"`
	Target       string `json:"target"`
	TrustType    string `json:"trust_type"`
	ExternalID   string `json:"external_id"`
	RoleARN      string `json:"role_arn"`
}

type CrossAccountTrust struct {
	AccountID    string `json:"account_id"`
	RoleARN      string `json:"role_arn"`
	ExternalID   string `json:"external_id"`
	Condition    string `json:"condition"`
}

type AWSCloudInfo struct {
	AccountID   string   `json:"account_id"`
	Roles       []string `json:"roles"`
	Policies    []string `json:"policies"`
	Services    []string `json:"services"`
	Regions     []string `json:"regions"`
}

type AzureCloudInfo struct {
	TenantID    string   `json:"tenant_id"`
	Subscriptions []string `json:"subscriptions"`
	ResourceGroups []string `json:"resource_groups"`
	AppRegistrations []string `json:"app_registrations"`
}

type GCPCloudInfo struct {
	ProjectID   string   `json:"project_id"`
	SAEmail     string   `json:"sa_email"`
	Buckets     []string `json:"buckets"`
	Instances   []string `json:"instances"`
}

type TrustRelationship struct {
	Type       string `json:"type"`
	Principal  string `json:"principal"`
	Resource   string `json:"resource"`
	Condition  string `json:"condition"`
}

type PivotPath struct {
	Steps      []PivotStep `json:"steps"`
	TotalHops  int         `json:"total_hops"`
	RiskLevel  string      `json:"risk_level"`
}

type PivotStep struct {
	Cloud      string `json:"cloud"`
	Service    string `json:"service"`
	Resource   string `json:"resource"`
	Action     string `json:"action"`
}
