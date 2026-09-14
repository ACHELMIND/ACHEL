package c2implant

import (
	"encoding/json"
	"fmt"
	"time"
)

type ChannelType string

const (
	ChannelHTTP  ChannelType = "http"
	ChannelHTTPS ChannelType = "https"
	ChannelDNS   ChannelType = "dns"
	ChannelTCPS  ChannelType = "tcps"
	ChannelWSS   ChannelType = "wss"
)

type ImplantConfig struct {
	ServerURL   string        `json:"server_url"`
	SleepTime   time.Duration `json:"sleep_time"`
	Jitter      float64       `json:"jitter"`
	CryptoKey   []byte        `json:"crypto_key"`
	KillDate    time.Time     `json:"kill_date"`
	MaxRetries  int           `json:"max_retries"`
	ChannelType ChannelType   `json:"channel_type"`
	ImplantID   string        `json:"implant_id"`
	TeamID      string        `json:"team_id"`
	OperatorID  string        `json:"operator_id"`
}

func DefaultConfig() *ImplantConfig {
	return &ImplantConfig{
		ServerURL:   "https://teamserver.local:8443",
		SleepTime:   30 * time.Second,
		Jitter:      0.25,
		CryptoKey:   nil,
		KillDate:    time.Now().Add(365 * 24 * time.Hour),
		MaxRetries:  5,
		ChannelType: ChannelHTTPS,
		ImplantID:   "",
		TeamID:      "default",
		OperatorID:  "operator",
	}
}

func LoadConfig(data []byte) (*ImplantConfig, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty config data")
	}

	cfg := &ImplantConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

func (c *ImplantConfig) Validate() error {
	if c.ServerURL == "" {
		return fmt.Errorf("server URL is required")
	}

	if c.SleepTime < time.Second {
		return fmt.Errorf("sleep time must be at least 1 second")
	}

	if c.Jitter < 0 || c.Jitter > 1.0 {
		return fmt.Errorf("jitter must be between 0 and 1.0")
	}

	if c.MaxRetries < 1 {
		return fmt.Errorf("max retries must be at least 1")
	}

	if !c.KillDate.IsZero() && c.KillDate.Before(time.Now()) {
		return fmt.Errorf("kill date is in the past")
	}

	switch c.ChannelType {
	case ChannelHTTP, ChannelHTTPS, ChannelDNS, ChannelTCPS, ChannelWSS:
	default:
		return fmt.Errorf("invalid channel type: %s", c.ChannelType)
	}

	return nil
}

func (c *ImplantConfig) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *ImplantConfig) IsExpired() bool {
	if c.KillDate.IsZero() {
		return false
	}
	return time.Now().After(c.KillDate)
}
