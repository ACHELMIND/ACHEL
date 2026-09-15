package socialengineering

import "time"

type PretextType int

const (
	PretextTypeCEOFraud PretextType = iota
	PretextTypeTechSupport
	PretextTypeVendorImpersonation
	PretextTypeJobOffer
	PretextTypeUrgentRequest
	PretextTypePackageDelivery
	PretextTypeInvoiceFraud
	PretextTypeCredentialHarvest
)

func (p PretextType) String() string {
	return [...]string{
		"CEO Fraud", "Tech Support", "Vendor Impersonation",
		"Job Offer", "Urgent Request", "Package Delivery",
		"Invoice Fraud", "Credential Harvest",
	}[p]
}

type PhishingConfig struct {
	SMTPServer    string
	SMTPPort      int
	SenderEmail   string
	SenderName    string
	TargetDomains []string
	TrackingID    string
	WebhookURL    string
	RedirectURL   string
	TemplateDir   string
	CredentialURL string
}

type PhishingResult struct {
	ID            string      `json:"id"`
	CampaignName  string      `json:"campaign_name"`
	Type          PretextType `json:"type"`
	EmailsSent    int         `json:"emails_sent"`
	OpensDetected int         `json:"opens_detected"`
	ClicksDetected int        `json:"clicks_detected"`
	CredsCaptured int         `json:"creds_captured"`
	Templates     []EmailTemplate `json:"templates"`
	Timestamp     time.Time   `json:"timestamp"`
}

type EmailTemplate struct {
	Name     string `json:"name"`
	Subject  string `json:"subject"`
	From     string `json:"from"`
	HTMLBody string `json:"html_body"`
	TextBody string `json:"text_body"`
	Pretext  PretextType `json:"pretext"`
}

type CampaignConfig struct {
	Name         string
	Targets      []TargetInfo
	Pretext      PretextType
	SendTime     time.Time
	Interval     time.Duration
	MaxRetries   int
	TrackingOn   bool
}

type TargetInfo struct {
	Name      string `json:"name"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	Role      string `json:"role"`
	Company   string `json:"company"`
	Division  string `json:"division"`
}

type QRPhishConfig struct {
	URL         string
	LogoPath    string
	OutputPath  string
	Size        int
	ErrorLevel  string
}

type VishingConfig struct {
	CallerID    string
	Script      string
	TargetPhone string
	Company     string
	Department  string
}

type SmishingConfig struct {
	Message     string
	SenderID    string
	TargetPhone string
	TrackingURL string
}
