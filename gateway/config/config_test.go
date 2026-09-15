package config

import (
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Gateway.Addr != "0.0.0.0" {
		t.Errorf("Gateway.Addr = %q, want %q", cfg.Gateway.Addr, "0.0.0.0")
	}
	if cfg.Gateway.Port != 3000 {
		t.Errorf("Gateway.Port = %d, want %d", cfg.Gateway.Port, 3000)
	}
	if cfg.Gateway.Sleep != 30*time.Second {
		t.Errorf("Gateway.Sleep = %v, want %v", cfg.Gateway.Sleep, 30*time.Second)
	}
	if cfg.Gateway.Jitter != 0.25 {
		t.Errorf("Gateway.Jitter = %f, want 0.25", cfg.Gateway.Jitter)
	}
	if cfg.Gateway.MaxAgents != 1000 {
		t.Errorf("Gateway.MaxAgents = %d, want %d", cfg.Gateway.MaxAgents, 1000)
	}
	if cfg.Database.Driver != "sqlite3" {
		t.Errorf("Database.Driver = %q, want %q", cfg.Database.Driver, "sqlite3")
	}
	if cfg.C2.Port != 8080 {
		t.Errorf("C2.Port = %d, want %d", cfg.C2.Port, 8080)
	}
	if cfg.Auth.JWTExpiry != 24*time.Hour {
		t.Errorf("Auth.JWTExpiry = %v, want %v", cfg.Auth.JWTExpiry, 24*time.Hour)
	}
	if cfg.Auth.EnableRBAC != true {
		t.Error("Auth.EnableRBAC should be true")
	}
}

func TestLoadConfig_EnvOverride(t *testing.T) {
	os.Setenv("GATEWAY_ADDR", "127.0.0.1")
	os.Setenv("GATEWAY_SECRET", "my-secret")
	defer os.Unsetenv("GATEWAY_ADDR")
	defer os.Unsetenv("GATEWAY_SECRET")

	cfg := LoadConfig()

	if cfg.Gateway.Addr != "127.0.0.1" {
		t.Errorf("Gateway.Addr = %q, want %q", cfg.Gateway.Addr, "127.0.0.1")
	}
	if cfg.Auth.JWTSecret != "my-secret" {
		t.Errorf("Auth.JWTSecret = %q, want %q", cfg.Auth.JWTSecret, "my-secret")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	os.Unsetenv("GATEWAY_ADDR")
	os.Unsetenv("GATEWAY_SECRET")

	cfg := LoadConfig()

	if cfg.Gateway.Addr != "0.0.0.0" {
		t.Errorf("Gateway.Addr = %q, want %q", cfg.Gateway.Addr, "0.0.0.0")
	}
	if cfg.Auth.JWTSecret != "angel-jwt-secret-change-me" {
		t.Errorf("Auth.JWTSecret = %q, want default", cfg.Auth.JWTSecret)
	}
}
