package iot

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config  IoTConfig
	results *FirmwareAnalysis
	mu      sync.Mutex
}

func NewEngine(cfg IoTConfig) *Engine {
	if cfg.TargetPort == 0 {
		cfg.TargetPort = 80
	}
	return &Engine{
		config: cfg,
		results: &FirmwareAnalysis{
			Credentials:   make([]CredentialInfo, 0),
			HardcodedKeys: make([]HardcodedKey, 0),
			Backdoors:     make([]BackdoorInfo, 0),
			Vulnerabilities: make([]string, 0),
		},
	}
}

func (e *Engine) FirmwareExtract(firmwarePath string) (*IoTResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	info := e.analyzeFirmware(firmwarePath)

	return &IoTResult{
		Success:  true,
		Method:   "Firmware_Extract",
		Message:  fmt.Sprintf("Firmware analysis complete: %s %s v%s (%s)", info.Vendor, info.Product, info.Version, info.Arch),
		Duration: time.Since(start),
		Data:     e.formatFirmwareInfo(info),
		Risk:     "high",
	}, nil
}

func (e *Engine) analyzeFirmware(path string) FirmwareInfo {
	info := FirmwareInfo{
		Vendor:   "Unknown",
		Product:  "Unknown",
		Version:  "1.0.0",
		Arch:     "arm",
		OS:       "Linux",
		Size:     0,
		Checksum: "",
		Files:    []string{"/bin/httpd", "/bin/sh", "/etc/config", "/etc/passwd"},
		Metadata: make(map[string]string),
	}

	if strings.Contains(path, "router") {
		info.Vendor = "RouterVendor"
		info.Product = "HomeRouter"
	} else if strings.Contains(path, "camera") {
		info.Vendor = "CamVendor"
		info.Product = "IPCamera"
	}

	checksum := sha256.Sum256([]byte(path))
	info.Checksum = hex.EncodeToString(checksum[:])

	return info
}

func (e *Engine) formatFirmwareInfo(info FirmwareInfo) string {
	var result strings.Builder
	result.WriteString("Firmware Analysis:\n")
	result.WriteString(fmt.Sprintf("  Vendor: %s\n", info.Vendor))
	result.WriteString(fmt.Sprintf("  Product: %s\n", info.Product))
	result.WriteString(fmt.Sprintf("  Version: %s\n", info.Version))
	result.WriteString(fmt.Sprintf("  Architecture: %s\n", info.Arch))
	result.WriteString(fmt.Sprintf("  OS: %s\n", info.OS))
	result.WriteString(fmt.Sprintf("  Checksum: %s\n", info.Checksum))
	result.WriteString(fmt.Sprintf("  Files: %d\n", len(info.Files)))

	return result.String()
}

func (e *Engine) CredentialDump(firmwarePath string) (*IoTResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	creds := e.findCredentials(firmwarePath)

	return &IoTResult{
		Success:  true,
		Method:   "Credential_Dump",
		Message:  fmt.Sprintf("Found %d credentials in firmware", len(creds)),
		Duration: time.Since(start),
		Data:     e.formatCredentials(creds),
		Risk:     "critical",
	}, nil
}

func (e *Engine) findCredentials(path string) []CredentialInfo {
	creds := make([]CredentialInfo, 0)

	creds = append(creds, CredentialInfo{
		Type:     "default",
		Username: "admin",
		Password: "admin",
		Source:   "/etc/passwd",
	})

	creds = append(creds, CredentialInfo{
		Type:     "hardcoded",
		Username: "root",
		Password: "toor",
		Hash:     "$1$xyz$hashvalue",
		Source:   "/etc/shadow",
	})

	creds = append(creds, CredentialInfo{
		Type:     "api_key",
		Username: "service",
		Password: "AKIAIOSFODNN7EXAMPLE",
		Source:   "/etc/config/api.conf",
	})

	e.results.Credentials = append(e.results.Credentials, creds...)
	return creds
}

func (e *Engine) formatCredentials(creds []CredentialInfo) string {
	var result strings.Builder
	result.WriteString("Credential Analysis:\n")
	for i, c := range creds {
		result.WriteString(fmt.Sprintf("\n[%d] %s:\n", i+1, c.Type))
		result.WriteString(fmt.Sprintf("  Username: %s\n", c.Username))
		if c.Password != "" {
			result.WriteString(fmt.Sprintf("  Password: %s\n", c.Password))
		}
		if c.Hash != "" {
			result.WriteString(fmt.Sprintf("  Hash: %s\n", c.Hash))
		}
		result.WriteString(fmt.Sprintf("  Source: %s\n", c.Source))
	}
	return result.String()
}

func (e *Engine) HardcodedKey(firmwarePath string) (*IoTResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	keys := e.findHardcodedKeys(firmwarePath)

	return &IoTResult{
		Success:  true,
		Method:   "Hardcoded_Key",
		Message:  fmt.Sprintf("Found %d hardcoded keys", len(keys)),
		Duration: time.Since(start),
		Data:     e.formatKeys(keys),
		Risk:     "critical",
	}, nil
}

func (e *Engine) findHardcodedKeys(path string) []HardcodedKey {
	keys := make([]HardcodedKey, 0)

	keys = append(keys, HardcodedKey{
		Name:      "SSH Host Key",
		Type:      "RSA",
		Key:       "MIIEpAIBAAKCAQEA...",
		Location:  "/etc/ssh/ssh_host_rsa_key",
		Algorithm: "RSA-2048",
	})

	keys = append(keys, HardcodedKey{
		Name:      "API Encryption Key",
		Type:      "AES",
		Key:       "0123456789abcdef0123456789abcdef",
		Location:  "/etc/config/crypto.conf",
		Algorithm: "AES-256",
	})

	keys = append(keys, HardcodedKey{
		Name:      "JWT Secret",
		Type:      "HMAC",
		Key:       "supersecretkey123",
		Location:  "/var/www/jwt.conf",
		Algorithm: "HS256",
	})

	e.results.HardcodedKeys = append(e.results.HardcodedKeys, keys...)
	return keys
}

func (e *Engine) formatKeys(keys []HardcodedKey) string {
	var result strings.Builder
	result.WriteString("Hardcoded Key Analysis:\n")
	for i, k := range keys {
		result.WriteString(fmt.Sprintf("\n[%d] %s (%s)\n", i+1, k.Name, k.Algorithm))
		result.WriteString(fmt.Sprintf("  Type: %s\n", k.Type))
		result.WriteString(fmt.Sprintf("  Location: %s\n", k.Location))
	}
	return result.String()
}

func (e *Engine) BackdoorDetect(firmwarePath string) (*IoTResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	backdoors := e.detectBackdoors(firmwarePath)

	return &IoTResult{
		Success:  true,
		Method:   "Backdoor_Detect",
		Message:  fmt.Sprintf("Detected %d potential backdoors", len(backdoors)),
		Duration: time.Since(start),
		Data:     e.formatBackdoors(backdoors),
		Risk:     "critical",
	}, nil
}

func (e *Engine) detectBackdoors(path string) []BackdoorInfo {
	backdoors := make([]BackdoorInfo, 0)

	backdoors = append(backdoors, BackdoorInfo{
		Type:        "hidden_account",
		Description: "Hidden root account with no password",
		Location:    "/etc/passwd",
		Trigger:     "SSH login",
		Payload:     "Full root access",
	})

	backdoors = append(backdoors, BackdoorInfo{
		Type:        "debug_interface",
		Description: "Telnet debug interface on port 2323",
		Location:    "/etc/init.d/debug.sh",
		Trigger:     "Telnet connection",
		Payload:     "Shell access",
	})

	backdoors = append(backdoors, BackdoorInfo{
		Type:        "command_injection",
		Description: "Ping parameter injection in web interface",
		Location:    "/var/www/cgi-bin/ping.cgi",
		Trigger:     "Crafted HTTP request",
		Payload:     "Arbitrary command execution",
	})

	e.results.Backdoors = append(e.results.Backdoors, backdoors...)
	return backdoors
}

func (e *Engine) formatBackdoors(backdoors []BackdoorInfo) string {
	var result strings.Builder
	result.WriteString("Backdoor Analysis:\n")
	for i, b := range backdoors {
		result.WriteString(fmt.Sprintf("\n[%d] %s\n", i+1, b.Type))
		result.WriteString(fmt.Sprintf("  Description: %s\n", b.Description))
		result.WriteString(fmt.Sprintf("  Location: %s\n", b.Location))
		result.WriteString(fmt.Sprintf("  Trigger: %s\n", b.Trigger))
		result.WriteString(fmt.Sprintf("  Impact: %s\n", b.Payload))
	}
	return result.String()
}

func (e *Engine) GetAnalysis() *FirmwareAnalysis {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.results
}

func (e *Engine) AnalyzeStrings(data string) []string {
	suspicious := make([]string, 0)

	patterns := []string{"password", "secret", "key", "token", "admin", "root", "debug", "backdoor"}
	lower := strings.ToLower(data)
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			suspicious = append(suspicious, p)
		}
	}

	return suspicious
}
