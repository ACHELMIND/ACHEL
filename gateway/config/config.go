package config

import (
	"os"
	"path/filepath"
	"time"
)

type ServerConfig struct {
	Gateway   GatewayConfig `json:"gateway"`
	Database  DBConfig      `json:"database"`
	C2        C2Config      `json:"c2"`
	Auth      AuthConfig    `json:"auth"`
}

type GatewayConfig struct {
	Addr      string        `json:"addr"`
	Port      int           `json:"port"`
	Sleep     time.Duration `json:"sleep"`
	Jitter    float64       `json:"jitter"`
	MaxAgents int           `json:"max_agents"`
}

type DBConfig struct {
	Driver string `json:"driver"`
	DSN    string `json:"dsn"`
}

type C2Config struct {
	Addr      string        `json:"addr"`
	Port      int           `json:"port"`
	Sleep     time.Duration `json:"sleep"`
	Jitter    float64       `json:"jitter"`
	MaxAgents int           `json:"max_agents"`
}

type AuthConfig struct {
	JWTSecret  string        `json:"jwt_secret"`
	JWTExpiry  time.Duration `json:"jwt_expiry"`
	EnableRBAC bool          `json:"enable_rbac"`
}

func DefaultConfig() *ServerConfig {
	return &ServerConfig{
		Gateway: GatewayConfig{
			Addr:      "0.0.0.0",
			Port:      3000,
			Sleep:     30 * time.Second,
			Jitter:    0.25,
			MaxAgents: 1000,
		},
		Database: DBConfig{
			Driver: "sqlite3",
			DSN:    filepath.Join(os.Getenv("HOME"), ".angel", "gateway.db"),
		},
		C2: C2Config{
			Addr:      "0.0.0.0",
			Port:      8080,
			Sleep:     30 * time.Second,
			Jitter:    0.25,
			MaxAgents: 1000,
		},
		Auth: AuthConfig{
			JWTSecret:  "angel-jwt-secret-change-me",
			JWTExpiry:  24 * time.Hour,
			EnableRBAC: true,
		},
	}
}

func LoadConfig() *ServerConfig {
	cfg := DefaultConfig()

	if addr := os.Getenv("GATEWAY_ADDR"); addr != "" {
		cfg.Gateway.Addr = addr
	}
	if secret := os.Getenv("GATEWAY_SECRET"); secret != "" {
		cfg.Auth.JWTSecret = secret
	}

	return cfg
}
