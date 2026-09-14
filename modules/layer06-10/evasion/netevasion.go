package evasion

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"strings"
	"sync"
	"time"
)

type NetworkEvasion struct {
	config         *NetworkEvasionConfig
	currentIPIdx   int
	currentUAIdx   int
	currentTLSIdx  int
	trafficState   *TrafficState
	mu             sync.RWMutex
}

type TrafficState struct {
	Pattern       []byte
	LastMorph     time.Time
	MorphCount    int
	JitterActive  bool
}

func NewNetworkEvasion(config *NetworkEvasionConfig) *NetworkEvasion {
	if config == nil {
		config = NewDefaultNetworkConfig()
	}

	ne := &NetworkEvasion{
		config:       config,
		trafficState: &TrafficState{},
	}

	if len(ne.config.IPPool) == 0 {
		ne.config.IPPool = []string{
			"198.51.100.0",
			"203.0.113.0",
			"192.0.2.0",
		}
	}

	return ne
}

func (ne *NetworkEvasion) RotateIP() string {
	ne.mu.Lock()
	defer ne.mu.Unlock()

	if len(ne.config.IPPool) == 0 {
		return "0.0.0.0"
	}

	ip := ne.config.IPPool[ne.currentIPIdx]
	ne.currentIPIdx = (ne.currentIPIdx + 1) % len(ne.config.IPPool)
	return ip
}

func (ne *NetworkEvasion) RotateUserAgent() string {
	ne.mu.Lock()
	defer ne.mu.Unlock()

	if len(ne.config.UserAgents) == 0 {
		return "Mozilla/5.0"
	}

	ua := ne.config.UserAgents[ne.currentUAIdx]
	ne.currentUAIdx = (ne.currentUAIdx + 1) % len(ne.config.UserAgents)
	return ua
}

func (ne *NetworkEvasion) RotateTLSFingerprint() string {
	ne.mu.Lock()
	defer ne.mu.Unlock()

	if len(ne.config.TLSFingerprints) == 0 {
		return "unknown"
	}

	fp := ne.config.TLSFingerprints[ne.currentTLSIdx]
	ne.currentTLSIdx = (ne.currentTLSIdx + 1) % len(ne.config.TLSFingerprints)
	return fp
}

func (ne *NetworkEvasion) EncodeDNS(data []byte) string {
	ne.mu.RLock()
	defer ne.mu.RUnlock()

	encodingType := ne.config.DNSEncodingType
	switch encodingType {
	case "hex":
		return ne.encodeDNSHex(data)
	case "base32":
		return ne.encodeDNSBase32(data)
	case "base64dns":
		return ne.encodeDNSBase64(data)
	case "chunked":
		return ne.encodeDNSChunked(data)
	default:
		return ne.encodeDNSHex(data)
	}
}

func (ne *NetworkEvasion) encodeDNSHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	encoded := hex.EncodeToString(data)
	chunks := make([]string, 0)
	chunkSize := 16

	for i := 0; i < len(encoded); i += chunkSize {
		end := i + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		chunk := encoded[i:end]
		chunks = append(chunks, chunk)
	}

	return strings.Join(chunks, ".")
}

func (ne *NetworkEvasion) encodeDNSBase32(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	encoded := ""
	bits := 0
	value := 0

	for _, b := range data {
		value = (value << 8) | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			encoded += string(base32Chars[(value>>uint(bits))&0x1F])
		}
	}
	if bits > 0 {
		encoded += string(base32Chars[(value<<uint(5-bits))&0x1F])
	}

	return strings.ToLower(encoded)
}

func (ne *NetworkEvasion) encodeDNSBase64(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	encoded := ""
	bits := 0
	value := 0

	for _, b := range data {
		value = (value << 8) | int(b)
		bits += 8
		for bits >= 6 {
			bits -= 6
			encoded += string(base64Chars[(value>>uint(bits))&0x3F])
		}
	}
	if bits > 0 {
		encoded += string(base64Chars[(value<<uint(6-bits))&0x3F])
	}

	for len(encoded)%4 != 0 {
		encoded += "="
	}

	return encoded
}

func (ne *NetworkEvasion) encodeDNSChunked(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	chunkSize := 12
	chunks := make([]string, 0)
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := hex.EncodeToString(data[i:end])
		chunks = append(chunks, chunk)
	}
	return strings.Join(chunks, ".")
}

func (ne *NetworkEvasion) MorphTrafficPattern() []byte {
	ne.mu.Lock()
	defer ne.mu.Unlock()

	if !ne.config.TrafficMorphing {
		return ne.trafficState.Pattern
	}

	basePattern := []byte{0x16, 0x03, 0x01, 0x00}
	newPattern := make([]byte, len(basePattern))
	copy(newPattern, basePattern)

	jitterLen := mathrand.Intn(32) + 4
	jitterBytes := make([]byte, jitterLen)
	rand.Read(jitterBytes)

	morphed := append(newPattern, jitterBytes...)

	prefix := []byte{0x47, 0x45, 0x54, 0x20}
	suffix := []byte{0x0D, 0x0A, 0x0D, 0x0A}
	morphed = append(prefix, morphed...)
	morphed = append(morphed, suffix...)

	ne.trafficState.Pattern = morphed
	ne.trafficState.LastMorph = time.Now()
	ne.trafficState.MorphCount++

	return morphed
}

func (ne *NetworkEvasion) ApplyJitter(interval time.Duration) time.Duration {
	ne.mu.RLock()
	defer ne.mu.RUnlock()

	if ne.config.JitterPercent <= 0 {
		return interval
	}

	jitter := time.Duration(float64(interval) * ne.config.JitterPercent)
	offset := time.Duration(mathrand.Int63n(int64(jitter*2))) - jitter

	newInterval := interval + offset
	if newInterval < 100*time.Millisecond {
		newInterval = 100 * time.Millisecond
	}
	return newInterval
}

func (ne *NetworkEvasion) GenerateRandomDomain(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}

func (ne *NetworkEvasion) ObfuscatePayload(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	key := make([]byte, len(data))
	rand.Read(key)

	obfuscated := make([]byte, len(data))
	for i := range data {
		obfuscated[i] = data[i] ^ key[i]
	}

	result := make([]byte, 0, len(key)+len(obfuscated))
	result = append(result, key...)
	result = append(result, obfuscated...)
	return result
}

func (ne *NetworkEvasion) DeobfuscatePayload(data []byte) []byte {
	if len(data) < 2 {
		return data
	}

	keyLen := len(data) / 2
	key := data[:keyLen]
	obfuscated := data[keyLen:]

	deobfuscated := make([]byte, len(obfuscated))
	for i := range obfuscated {
		deobfuscated[i] = obfuscated[i] ^ key[i]
	}
	return deobfuscated
}

func (ne *NetworkEvasion) GetTrafficState() *TrafficState {
	ne.mu.RLock()
	defer ne.mu.RUnlock()
	return &TrafficState{
		Pattern:      ne.trafficState.Pattern,
		LastMorph:    ne.trafficState.LastMorph,
		MorphCount:   ne.trafficState.MorphCount,
		JitterActive: ne.config.JitterPercent > 0,
	}
}

func (ne *NetworkEvasion) GetConfig() *NetworkEvasionConfig {
	return ne.config
}

func (ne *NetworkEvasion) String() string {
	ne.mu.RLock()
	defer ne.mu.RUnlock()
	return fmt.Sprintf("NetworkEvasion[ips=%d, uas=%d, tls=%d, jitter=%.2f]",
		len(ne.config.IPPool),
		len(ne.config.UserAgents),
		len(ne.config.TLSFingerprints),
		ne.config.JitterPercent)
}
