package tls13

import "time"

type TLS13Config struct {
	TargetHost string        `json:"target_host"`
	TargetPort int           `json:"target_port"`
	Timeout    time.Duration `json:"timeout"`
	SNI        string        `json:"sni"`
}

type TLSResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Details  string        `json:"details"`
	Risk     string        `json:"risk"`
}

type TLSAttack struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Protocol    string `json:"protocol"`
}

type CipherSuite struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Bits  int    `json:"bits"`
	Grade string `json:"grade"`
}

type TLSVersion struct {
	Version     uint16 `json:"version"`
	Name        string `json:"name"`
	Support     bool   `json:"support"`
	Vulnerable  bool   `json:"vulnerable"`
}

type TicketInfo struct {
	TicketAge    int    `json:"ticket_age"`
	TicketLength int    `json:"ticket_length"`
	Resumption   bool   `json:"resumption"`
	PSK          string `json:"psk"`
}

type MiddleboxInfo struct {
	Intercepting bool   `json:"intercepting"`
	Software     string `json:"software"`
	Version      string `json:"version"`
	InfoLeak     bool   `json:"info_leak"`
}

type DowngradeInfo struct {
	OriginalVersion string `json:"original_version"`
	TargetVersion   string `json:"target_version"`
	Successful      bool   `json:"successful"`
	Technique       string `json:"technique"`
}

type PaddingOracleInfo struct {
	Vulnerable  bool   `json:"vulnerable"`
	BlockSize   int    `json:"block_size"`
	Technique   string `json:"technique"`
	Confidence  string `json:"confidence"`
}
