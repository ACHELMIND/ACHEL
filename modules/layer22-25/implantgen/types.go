package implantgen

import (
	"time"
)

type Arch string

const (
	ArchX86   Arch = "x86"
	ArchX64   Arch = "x64"
	ArchARM64 Arch = "arm64"
)

type OSType string

const (
	OSWindows OSType = "windows"
	OSLinux   OSType = "linux"
	OSDarwin  OSType = "darwin"
)

type ImplantBinary struct {
	ID         string            `json:"id"`
	Data       []byte            `json:"data"`
	Size       int               `json:"size"`
	Arch       Arch              `json:"arch"`
	OS         OSType            `json:"os"`
	Encrypted  bool              `json:"encrypted"`
	Obfuscated bool              `json:"obfuscated"`
	Checksum   string            `json:"checksum"`
	CreatedAt  time.Time         `json:"created_at"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type GeneratorConfig struct {
	DefaultArch      Arch
	DefaultOS        OSType
	MaxBinarySize    int
	EnableEncryption bool
	ObfuscationLevel int
}

type GenerateParams struct {
	Name           string            `json:"name"`
	Arch           Arch              `json:"arch"`
	OS             OSType            `json:"os"`
	Format         string            `json:"format"`
	Config         *BeaconConfig     `json:"config,omitempty"`
	Encrypt        bool              `json:"encrypt"`
	Key            []byte            `json:"key,omitempty"`
	Obfuscate      int               `json:"obfuscate"`
	Shellcode      bool              `json:"shellcode"`
	ShellcodeArch  Arch              `json:"shellcode_arch"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type BeaconConfig struct {
	ID           string        `json:"id"`
	CallbackURLs []string      `json:"callback_urls"`
	SleepTime    time.Duration `json:"sleep_time"`
	Jitter       float64       `json:"jitter"`
	MaxRetries   int           `json:"max_retries"`
	NoiseLevel   int           `json:"noise_level"`
	EncKey       []byte        `json:"enc_key,omitempty"`
	Cookie       string        `json:"cookie,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type PayloadEncryptor struct {
	key []byte
}

type TemplateInfo struct {
	Name string
	Arch Arch
	OS   OSType
	Size int
}

type TemplateManager struct {
	templates map[string]*templateEntry
}

type templateEntry struct {
	data []byte
	info TemplateInfo
}

func NewDefaultGeneratorConfig() *GeneratorConfig {
	return &GeneratorConfig{
		DefaultArch:      ArchX64,
		DefaultOS:        OSWindows,
		MaxBinarySize:    10 * 1024 * 1024,
		EnableEncryption: true,
		ObfuscationLevel: 2,
	}
}

func NewDefaultBeaconConfig() *BeaconConfig {
	return &BeaconConfig{
		ID:           "",
		CallbackURLs: []string{},
		SleepTime:    60 * time.Second,
		Jitter:       0.2,
		MaxRetries:   3,
		NoiseLevel:   1,
	}
}
