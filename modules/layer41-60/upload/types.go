package upload

import "time"

type UploadConfig struct {
	TargetURL     string        `json:"target_url"`
	FieldName     string        `json:"field_name"`
	AllowedExts   []string      `json:"allowed_exts"`
	MaxSize       int64         `json:"max_size"`
	Timeout       time.Duration `json:"timeout"`
}

type UploadResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Payload  string        `json:"payload"`
	Risk     string        `json:"risk"`
}

type BypassMethod struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Success     bool   `json:"success"`
}

type FileType struct {
	MIME        string   `json:"mime"`
	Extensions  []string `json:"extensions"`
	MagicBytes  []byte   `json:"magic_bytes"`
	MaxSize     int64    `json:"max_size"`
}

type UploadPayload struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	MagicBytes  []byte `json:"magic_bytes"`
	Size        int64  `json:"size"`
	Evasion     string `json:"evasion"`
}

type UploadAnalysis struct {
	OriginalName string `json:"original_name"`
	FinalName    string `json:"final_name"`
	MIMEType     string `json:"mime_type"`
	IsExecutable bool   `json:"is_executable"`
	RiskLevel    string `json:"risk_level"`
}

type ExtensionBypass struct {
	Original   string `json:"original"`
	Bypass     string `json:"bypass"`
	Technique  string `json:"technique"`
	CaseChange bool   `json:"case_change"`
}

type ContentTypeBypass struct {
	Original    string `json:"original"`
	FakeType    string `json:"fake_type"`
	Header      string `json:"header"`
}
