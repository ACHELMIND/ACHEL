package netevasion

import (
	"net/http"
	"testing"
	"time"
)

func TestNewNetEvasionEngine(t *testing.T) {
	engine := NewNetEvasionEngine(nil)
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if engine.config == nil {
		t.Fatal("expected non-nil config")
	}
	if engine.ipRot == nil {
		t.Error("expected non-nil ip rotator")
	}
	if engine.traffic == nil {
		t.Error("expected non-nil traffic morpher")
	}
	if engine.pktObf == nil {
		t.Error("expected non-nil packet obfuscator")
	}
	if engine.front == nil {
		t.Error("expected non-nil domain fronter")
	}
}

func TestNewNetEvasionEngineWithConfig(t *testing.T) {
	config := &NetEvasionConfig{
		Timeout:       10 * time.Second,
		JitterPercent: 0.5,
		ProxyList:     []string{"socks5://127.0.0.1:1080"},
		EncKey:        make([]byte, 32),
	}
	engine := NewNetEvasionEngine(config)
	if engine.config.Timeout != 10*time.Second {
		t.Error("expected custom timeout")
	}
}

func TestEvadeIPRotation(t *testing.T) {
	config := &NetEvasionConfig{
		ProxyList: []string{"socks5://127.0.0.1:1080", "http://proxy1:8080"},
		Timeout:   5 * time.Second,
	}
	engine := NewNetEvasionEngine(config)

	result, err := engine.Evade("ip_rotation")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Method != MethodIPRotation {
		t.Errorf("expected method ip_rotation, got %s", result.Method)
	}
}

func TestEvadeTrafficMorph(t *testing.T) {
	engine := NewNetEvasionEngine(nil)
	result, err := engine.Evade("traffic_morph")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Method != MethodTrafficMorph {
		t.Errorf("expected method traffic_morph, got %s", result.Method)
	}
}

func TestEvadePacketObfusc(t *testing.T) {
	engine := NewNetEvasionEngine(nil)
	result, err := engine.Evade("packet_obfusc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Method != MethodPacketObfusc {
		t.Errorf("expected method packet_obfusc, got %s", result.Method)
	}
}

func TestEvadeDomainFronting(t *testing.T) {
	engine := NewNetEvasionEngine(nil)
	result, err := engine.Evade("domain_fronting")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Method != MethodDomainFronting {
		t.Errorf("expected method domain_fronting, got %s", result.Method)
	}
}

func TestEvadeUnknownMethod(t *testing.T) {
	engine := NewNetEvasionEngine(nil)
	_, err := engine.Evade("unknown_method")
	if err == nil {
		t.Fatal("expected error for unknown method")
	}
}

func TestFullEvasion(t *testing.T) {
	config := &NetEvasionConfig{
		ProxyList: []string{"socks5://127.0.0.1:1080"},
	}
	engine := NewNetEvasionEngine(config)
	result, err := engine.FullEvasion()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Duration == 0 {
		t.Error("expected non-zero duration")
	}
}

func TestIPRotator(t *testing.T) {
	proxies := []string{"socks5://127.0.0.1:1080", "http://proxy1:8080", "socks5://proxy2:1080"}
	rotator := NewIPRotator(proxies)

	if rotator.ProxyCount() != 3 {
		t.Errorf("expected 3 proxies, got %d", rotator.ProxyCount())
	}

	ip, err := rotator.Rotate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip == "" {
		t.Error("expected non-empty IP")
	}

	currentIP := rotator.GetCurrentIP()
	if currentIP == "" {
		t.Error("expected current IP to be set")
	}
}

func TestIPRotatorEmpty(t *testing.T) {
	rotator := NewIPRotator([]string{})
	_, err := rotator.Rotate()
	if err == nil {
		t.Fatal("expected error rotating with no proxies")
	}
}

func TestIPRotatorAddRemove(t *testing.T) {
	rotator := NewIPRotator([]string{"proxy1:8080"})

	err := rotator.AddProxy("proxy2:8080")
	if err != nil {
		t.Fatalf("add proxy error: %v", err)
	}
	if rotator.ProxyCount() != 2 {
		t.Errorf("expected 2 proxies, got %d", rotator.ProxyCount())
	}

	err = rotator.AddProxy("proxy1:8080")
	if err == nil {
		t.Error("expected error adding duplicate proxy")
	}

	err = rotator.RemoveProxy("proxy2:8080")
	if err != nil {
		t.Fatalf("remove proxy error: %v", err)
	}
	if rotator.ProxyCount() != 1 {
		t.Errorf("expected 1 proxy after remove, got %d", rotator.ProxyCount())
	}

	err = rotator.RemoveProxy("nonexistent:8080")
	if err == nil {
		t.Error("expected error removing nonexistent proxy")
	}
}

func TestIPRotatorValidate(t *testing.T) {
	rotator := NewIPRotator([]string{"proxy1:8080", ""})
	invalid := rotator.ValidateAll()
	if len(invalid) != 1 {
		t.Errorf("expected 1 invalid proxy, got %d", len(invalid))
	}
}

func TestTrafficMorpher(t *testing.T) {
	morpher := NewTrafficMorpher()
	if morpher == nil {
		t.Fatal("expected non-nil morpher")
	}
}

func TestTrafficMorpherMorphHTTP(t *testing.T) {
	morpher := NewTrafficMorpher()
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "5.6.7.8")
	req.Header.Set("X-Request-ID", "req-123")

	morphed := morpher.MorphHTTP2Fingerprint(req)
	if morphed == nil {
		t.Fatal("expected non-nil morphed request")
	}
	if morphed.Header.Get("X-Forwarded-For") != "" {
		t.Error("expected X-Forwarded-For to be removed")
	}
	if morphed.Header.Get("X-Real-IP") != "" {
		t.Error("expected X-Real-IP to be removed")
	}
	if morphed.Header.Get("X-Request-ID") != "" {
		t.Error("expected X-Request-ID to be removed")
	}
	if morphed.Header.Get("User-Agent") == "" {
		t.Error("expected User-Agent to be set")
	}
}

func TestTrafficMorpherMorphNil(t *testing.T) {
	morpher := NewTrafficMorpher()
	result := morpher.MorphHTTP2Fingerprint(nil)
	if result != nil {
		t.Error("expected nil for nil request")
	}
}

func TestTrafficMorpherPacketSizes(t *testing.T) {
	morpher := NewTrafficMorpher()
	packets := [][]byte{
		{1, 2, 3},
		{4, 5, 6},
	}

	morphed := morpher.MorphPacketSizes(packets)
	if len(morphed) != 2 {
		t.Errorf("expected 2 packets, got %d", len(morphed))
	}
}

func TestTrafficMorpherPacketSizesEmpty(t *testing.T) {
	morpher := NewTrafficMorpher()
	morphed := morpher.MorphPacketSizes([][]byte{})
	if len(morphed) != 0 {
		t.Error("expected empty result for empty input")
	}
}

func TestTrafficMorpherRandomizeHeaders(t *testing.T) {
	morpher := NewTrafficMorpher()
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	randomized := morpher.RandomizeHeaders(headers)
	if randomized == nil {
		t.Error("expected non-nil randomized headers")
	}
}

func TestTrafficMorpherTLSFingerprint(t *testing.T) {
	morpher := NewTrafficMorpher()
	err := morpher.MorphTLSFingerprint(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTrafficMorpherSleepJitter(t *testing.T) {
	morpher := NewTrafficMorpher()
	data := []byte("test")
	result := morpher.AddSleepJitter(data, 0.0)
	if len(result) != len(data) {
		t.Error("expected same length with 0 jitter")
	}

	result = morpher.AddSleepJitter(data, 1.5)
	if len(result) != len(data) {
		t.Error("expected same length with out-of-range jitter")
	}
}

func TestPacketObfuscator(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	po := NewPacketObfuscator(key)
	if po == nil {
		t.Fatal("expected non-nil obfuscator")
	}
}

func TestPacketObfuscatorEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	po := NewPacketObfuscator(key)

	data := []byte("secret packet data")
	encrypted, err := po.Encrypt(data)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	decrypted, err := po.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}

	if string(decrypted) != string(data) {
		t.Error("decrypted data mismatch")
	}
}

func TestPacketObfuscatorEncryptDecryptEmpty(t *testing.T) {
	key := make([]byte, 32)
	po := NewPacketObfuscator(key)

	data := []byte{}
	encrypted, err := po.Encrypt(data)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	decrypted, err := po.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}

	if len(decrypted) != 0 {
		t.Error("expected empty decrypted data")
	}
}

func TestPacketObfuscatorDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	po := NewPacketObfuscator(key)

	_, err := po.Decrypt([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestPacketObfuscatorBase64(t *testing.T) {
	key := make([]byte, 32)
	po := NewPacketObfuscator(key)

	data := []byte("hello base64")
	encoded := po.EncodeBase64(data)
	if encoded == "" {
		t.Error("expected non-empty encoded string")
	}

	decoded, err := po.DecodeBase64(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if string(decoded) != string(data) {
		t.Error("base64 decode mismatch")
	}
}

func TestPacketObfuscatorObfuscate(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	po := NewPacketObfuscator(key)

	data := []byte("payload to obfuscate")
	obfuscated, err := po.ObfuscatePayload(data)
	if err != nil {
		t.Fatalf("obfuscate error: %v", err)
	}

	deobfuscated, err := po.DeobfuscatePayload(obfuscated)
	if err != nil {
		t.Fatalf("deobfuscate error: %v", err)
	}

	if string(deobfuscated) != string(data) {
		t.Error("deobfuscated data mismatch")
	}
}

func TestPacketObfuscatorDefaultKey(t *testing.T) {
	po := NewPacketObfuscator(nil)
	if po == nil {
		t.Fatal("expected non-nil obfuscator with default key")
	}

	data := []byte("test")
	encrypted, err := po.Encrypt(data)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}
	if len(encrypted) == 0 {
		t.Error("expected non-empty encrypted data")
	}
}

func TestDomainFronter(t *testing.T) {
	df := NewDomainFronter()
	if df == nil {
		t.Fatal("expected non-nil fronter")
	}

	cfg := &DomainFrontConfig{
		Target:   "https://real-target.com",
		CDN:      "cloudfront.net",
		Host:     "cdn-front.com",
		Protocol: "https",
	}

	df.AddFront("test-front", cfg)

	got, ok := df.GetFront("test-front")
	if !ok {
		t.Fatal("expected front to exist")
	}
	if got.Target != "https://real-target.com" {
		t.Error("expected correct target")
	}

	fronts := df.ListFronts()
	if len(fronts) != 1 {
		t.Errorf("expected 1 front, got %d", len(fronts))
	}

	df.RemoveFront("test-front")
	_, ok = df.GetFront("test-front")
	if ok {
		t.Error("expected front to be removed")
	}
}

func TestDomainFronterTestConnection(t *testing.T) {
	df := NewDomainFronter()
	cfg := &DomainFrontConfig{
		Target: "https://target.com",
		CDN:    "cdn.com",
		Host:   "front.com",
	}
	df.AddFront("test", cfg)

	result, err := df.TestConnection("test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.RequestStr == "" {
		t.Error("expected non-empty request string")
	}
}

func TestDomainFronterTestConnectionNotFound(t *testing.T) {
	df := NewDomainFronter()
	_, err := df.TestConnection("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent front")
	}
}

func TestDomainFronterBuildHTTPRequest(t *testing.T) {
	df := NewDomainFronter()
	cfg := &DomainFrontConfig{
		Target: "https://target.com",
		CDN:    "cdn.com",
		Host:   "front.com",
	}
	df.AddFront("test", cfg)

	headers, err := df.BuildHTTPRequest("test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if headers["Host"] != "front.com" {
		t.Error("expected correct Host header")
	}
}

func TestDomainFronterBuildHTTPRequestNotFound(t *testing.T) {
	df := NewDomainFronter()
	_, err := df.BuildHTTPRequest("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent front")
	}
}

func TestDomainFronterGetResults(t *testing.T) {
	df := NewDomainFronter()
	results := df.GetResults()
	if len(results) != 0 {
		t.Error("expected no results initially")
	}

	cfg := &DomainFrontConfig{
		Target: "https://target.com",
		CDN:    "cdn.com",
		Host:   "front.com",
	}
	df.AddFront("test", cfg)
	df.TestConnection("test")

	results = df.GetResults()
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}

	df.ClearResults()
	results = df.GetResults()
	if len(results) != 0 {
		t.Error("expected 0 results after clear")
	}
}

func TestDefaultNetEvasionConfig(t *testing.T) {
	config := DefaultNetEvasionConfig()
	if config.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.Timeout)
	}
	if config.JitterPercent != 0.25 {
		t.Errorf("expected 0.25 jitter, got %f", config.JitterPercent)
	}
}

func TestAllEvasionMethods(t *testing.T) {
	methods := AllEvasionMethods()
	if len(methods) != 4 {
		t.Errorf("expected 4 methods, got %d", len(methods))
	}
}
