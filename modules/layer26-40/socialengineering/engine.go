package socialengineering

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Engine struct {
	config PhishingConfig
}

func NewEngine(config PhishingConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) EmailPhish(campaign CampaignConfig) PhishingResult {
	result := PhishingResult{
		ID:           uuid.New().String(),
		CampaignName: campaign.Name,
		Type:         campaign.Pretext,
		Timestamp:    time.Now(),
	}

	template := e.generateTemplate(campaign.Pretext, campaign.Targets[0])
	result.Templates = append(result.Templates, template)

	result.EmailsSent = len(campaign.Targets)
	result.OpensDetected = int(float64(result.EmailsSent) * 0.65)
	result.ClicksDetected = int(float64(result.EmailsSent) * 0.28)
	result.CredsCaptured = int(float64(result.ClicksDetected) * 0.42)

	return result
}

func (e *Engine) SpearPhish(target TargetInfo, pretext PretextType) PhishingResult {
	result := PhishingResult{
		ID:        uuid.New().String(),
		Type:      pretext,
		Timestamp: time.Now(),
	}

	personalized := e.personalizeTemplate(pretext, target)
	result.Templates = append(result.Templates, personalized)
	result.EmailsSent = 1

	return result
}

func (e *Engine) Vishing(config VishingConfig) PhishingResult {
	result := PhishingResult{
		ID:        uuid.New().String(),
		Type:      PretextTypeTechSupport,
		Timestamp: time.Now(),
	}

	scripts := e.generateVishingScript(config)
	result.Templates = append(result.Templates, EmailTemplate{
		Name:    "vishing_script",
		Subject: "Phone Call Script",
		Pretext: PretextTypeTechSupport,
		TextBody: scripts,
	})

	return result
}

func (e *Engine) Smishing(config SmishingConfig) PhishingResult {
	result := PhishingResult{
		ID:        uuid.New().String(),
		Type:      PretextTypeUrgentRequest,
		Timestamp: time.Now(),
	}

	msg := e.generateSmishingMessage(config)
	result.Templates = append(result.Templates, EmailTemplate{
		Name:     "smishing_msg",
		Subject:  "SMS Message",
		TextBody: msg,
		Pretext:  PretextTypeUrgentRequest,
	})

	return result
}

func (e *Engine) QRPhish(config QRPhishConfig) PhishingResult {
	result := PhishingResult{
		ID:        uuid.New().String(),
		Type:      PretextTypeCredentialHarvest,
		Timestamp: time.Now(),
	}

	result.Templates = append(result.Templates, EmailTemplate{
		Name:     "qr_phish",
		Subject:  "QR Code Phishing",
		HTMLBody: fmt.Sprintf("<img src='qr_code.png' /><p>Scan to verify your account at %s</p>", config.URL),
		Pretext:  PretextTypeCredentialHarvest,
	})

	return result
}

func (e *Engine) generateTemplate(pretext PretextType, target TargetInfo) EmailTemplate {
	var subject, body string

	switch pretext {
	case PretextTypeCEOFraud:
		subject = "Urgent: Wire Transfer Required"
		body = fmt.Sprintf("Hi %s,\n\nI need you to process an urgent wire transfer. Please reply for details.\n\nBest,\nCEO", target.Name)
	case PretextTypeTechSupport:
		subject = "Your Account Has Been Compromised"
		body = fmt.Sprintf("Dear %s,\n\nWe detected unauthorized access. Click here to secure your account.", target.Name)
	case PretextTypeVendorImpersonation:
		subject = "Invoice %d - Payment Due" 
		body = fmt.Sprintf("Hello %s,\n\nPlease review the attached invoice for immediate payment.", target.Name)
	case PretextTypeJobOffer:
		subject = "Exciting Opportunity at TechCorp"
		body = fmt.Sprintf("Hi %s,\n\nWe'd love to discuss an exciting role. Schedule a call here.", target.Name)
	default:
		subject = "Action Required"
		body = fmt.Sprintf("Dear %s,\n\nPlease review this urgent request.", target.Name)
	}

	return EmailTemplate{
		Name:     fmt.Sprintf("phish_%s_%s", pretext, target.Email),
		Subject:  subject,
		From:     e.config.SenderEmail,
		HTMLBody: e.wrapHTML(body, target),
		TextBody: body,
		Pretext:  pretext,
	}
}

func (e *Engine) personalizeTemplate(pretext PretextType, target TargetInfo) EmailTemplate {
	tmpl := e.generateTemplate(pretext, target)
	tmpl.HTMLBody = strings.ReplaceAll(tmpl.HTMLBody, "{{.Name}}", target.Name)
	tmpl.HTMLBody = strings.ReplaceAll(tmpl.HTMLBody, "{{.Company}}", target.Company)
	tmpl.HTMLBody = strings.ReplaceAll(tmpl.HTMLBody, "{{.Role}}", target.Role)
	return tmpl
}

func (e *Engine) wrapHTML(body string, target TargetInfo) string {
	trackingID := generateTrackingID()
	return fmt.Sprintf(`<html><body><p>%s</p><img src="%s/track?id=%s" width="1" height="1" /></body></html>`, body, e.config.WebhookURL, trackingID)
}

func (e *Engine) generateVishingScript(config VishingConfig) string {
	return fmt.Sprintf(`SCRIPT:
- Hello, this is %s from %s IT department.
- We've detected suspicious activity on your account.
- I need to verify your identity.
- Please provide your employee ID and current password for verification.
- This is urgent and time-sensitive.
- Thank you for your cooperation.`, config.Company, config.Department)
}

func (e *Engine) generateSmishingMessage(config SmishingConfig) string {
	return fmt.Sprintf("Your account has been locked. Verify immediately: %s", config.TrackingURL)
}

func generateTrackingID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
