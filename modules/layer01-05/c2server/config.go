package c2server

import (
	"encoding/json"
	"fmt"
	"os"
)

type TeamserverConfig struct {
	BindAddr string `json:"bind_addr"`
	BindPort int    `json:"bind_port"`
	CryptoKey string `json:"crypto_key"`
	MaxAgents int    `json:"max_agents"`
	DBPath    string `json:"db_path"`
}

func DefaultConfig() *TeamserverConfig {
	return &TeamserverConfig{
		BindAddr:  "0.0.0.0",
		BindPort:  8443,
		CryptoKey: "default-secret-key-change-me",
		MaxAgents: 100,
		DBPath:    "teamserver.db",
	}
}

func LoadConfig(path string) (*TeamserverConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	config := DefaultConfig()
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return config, nil
}

func (c *TeamserverConfig) Validate() error {
	if c.BindAddr == "" {
		return fmt.Errorf("bind_addr is required")
	}
	if c.BindPort < 1 || c.BindPort > 65535 {
		return fmt.Errorf("bind_port must be between 1 and 65535")
	}
	if c.CryptoKey == "" {
		return fmt.Errorf("crypto_key is required")
	}
	if c.MaxAgents < 1 {
		return fmt.Errorf("max_agents must be at least 1")
	}
	if c.DBPath == "" {
		return fmt.Errorf("db_path is required")
	}
	return nil
}
