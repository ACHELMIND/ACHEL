package iot

import "time"

type IoTConfig struct {
	TargetIP    string        `json:"target_ip"`
	TargetPort  int           `json:"target_port"`
	FirmwarePath string       `json:"firmware_path"`
	Timeout     time.Duration `json:"timeout"`
}

type IoTResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Data     string        `json:"data"`
	Risk     string        `json:"risk"`
}

type FirmwareInfo struct {
	Vendor    string            `json:"vendor"`
	Product   string            `json:"product"`
	Version   string            `json:"version"`
	Arch      string            `json:"arch"`
	OS        string            `json:"os"`
	Size      int64             `json:"size"`
	Checksum  string            `json:"checksum"`
	Files     []string          `json:"files"`
	Metadata  map[string]string `json:"metadata"`
}

type IoTAttack struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Target      string `json:"target"`
	Severity    string `json:"severity"`
}

type CredentialInfo struct {
	Type     string `json:"type"`
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Source   string `json:"source"`
}

type HardcodedKey struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Key      string `json:"key"`
	Location string `json:"location"`
	Algorithm string `json:"algorithm"`
}

type BackdoorInfo struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Trigger     string `json:"trigger"`
	Payload     string `json:"payload"`
}

type FirmwareAnalysis struct {
	TotalFiles      int              `json:"total_files"`
	Executables     int              `json:"executables"`
	Scripts         int              `json:"scripts"`
	ConfigFiles     int              `json:"config_files"`
	Credentials     []CredentialInfo `json:"credentials"`
	HardcodedKeys   []HardcodedKey   `json:"hardcoded_keys"`
	Backdoors       []BackdoorInfo   `json:"backdoors"`
	Vulnerabilities []string         `json:"vulnerabilities"`
}
