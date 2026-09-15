package socialengineering

import (
	"testing"
)

func TestEmailPhish(t *testing.T) {
	engine := NewEngine(PhishingConfig{
		SMTPServer:  "smtp.example.com",
		SMTPPort:    587,
		SenderEmail: "hr@company.com",
		WebhookURL:  "https://track.example.com",
	})

	campaign := CampaignConfig{
		Name:    "Q4 Phishing Test",
		Targets: []TargetInfo{{Name: "John Doe", Email: "john@company.com", Role: "Engineer", Company: "Acme Corp"}},
		Pretext: PretextTypeCEOFraud,
	}

	result := engine.EmailPhish(campaign)

	if result.CampaignName != "Q4 Phishing Test" {
		t.Errorf("Expected campaign name 'Q4 Phishing Test', got %s", result.CampaignName)
	}
	if result.EmailsSent != 1 {
		t.Errorf("Expected 1 email sent, got %d", result.EmailsSent)
	}
	if len(result.Templates) == 0 {
		t.Error("Expected at least one template")
	}
}

func TestSpearPhish(t *testing.T) {
	engine := NewEngine(PhishingConfig{})

	target := TargetInfo{Name: "Jane Smith", Email: "jane@target.com", Company: "Target Corp"}
	result := engine.SpearPhish(target, PretextTypeTechSupport)

	if result.EmailsSent != 1 {
		t.Error("Expected 1 email for spear phishing")
	}
	if len(result.Templates) == 0 {
		t.Error("Expected template")
	}
	if result.Templates[0].Pretext != PretextTypeTechSupport {
		t.Error("Expected TechSupport pretext")
	}
}

func TestVishing(t *testing.T) {
	engine := NewEngine(PhishingConfig{})

	result := engine.Vishing(VishingConfig{
		Company:    "Acme Corp",
		Department: "IT Support",
	})

	if len(result.Templates) == 0 {
		t.Error("Expected vishing script")
	}
	if result.Templates[0].TextBody == "" {
		t.Error("Expected non-empty script body")
	}
}

func TestSmishing(t *testing.T) {
	engine := NewEngine(PhishingConfig{})

	result := engine.Smishing(SmishingConfig{
		Message:      "Your account is locked",
		TrackingURL:  "https://phish.example.com/track",
	})

	if len(result.Templates) == 0 {
		t.Error("Expected smishing message")
	}
}

func TestQRPhish(t *testing.T) {
	engine := NewEngine(PhishingConfig{})

	result := engine.QRPhish(QRPhishConfig{
		URL: "https://phish.example.com/login",
	})

	if len(result.Templates) == 0 {
		t.Error("Expected QR phishing template")
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(PhishingConfig{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
}

func TestPretextTypes(t *testing.T) {
	types := []PretextType{
		PretextTypeCEOFraud, PretextTypeTechSupport, PretextTypeVendorImpersonation,
		PretextTypeJobOffer, PretextTypeUrgentRequest, PretextTypePackageDelivery,
	}
	for _, pt := range types {
		if pt.String() == "" {
			t.Errorf("PretextType %d should have a string representation", pt)
		}
	}
}
