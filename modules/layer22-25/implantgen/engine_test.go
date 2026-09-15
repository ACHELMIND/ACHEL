package implantgen

import (
	"bytes"
	"testing"
	"time"
)

func TestNewImplantEngine(t *testing.T) {
	engine := NewImplantEngine(nil)
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if engine.config == nil {
		t.Fatal("expected non-nil config")
	}
	if engine.config.DefaultArch != ArchX64 {
		t.Errorf("expected default arch x64, got %s", engine.config.DefaultArch)
	}
}

func TestNewImplantEngineWithConfig(t *testing.T) {
	config := &GeneratorConfig{
		DefaultArch:      ArchARM64,
		DefaultOS:        OSLinux,
		MaxBinarySize:    5 * 1024 * 1024,
		EnableEncryption: false,
		ObfuscationLevel: 0,
	}
	engine := NewImplantEngine(config)
	if engine.config.DefaultArch != ArchARM64 {
		t.Errorf("expected arch arm64, got %s", engine.config.DefaultArch)
	}
	if engine.config.DefaultOS != OSLinux {
		t.Errorf("expected os linux, got %s", engine.config.DefaultOS)
	}
}

func TestGenerateWindows(t *testing.T) {
	engine := NewImplantEngine(nil)
	params := &GenerateParams{
		Name: "test-implant",
		Arch: ArchX64,
		OS:   OSWindows,
	}

	implant, err := engine.Generate(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if implant == nil {
		t.Fatal("expected non-nil implant")
	}
	if implant.ID == "" {
		t.Error("expected non-empty ID")
	}
	if implant.Arch != ArchX64 {
		t.Errorf("expected arch x64, got %s", implant.Arch)
	}
	if implant.OS != OSWindows {
		t.Errorf("expected os windows, got %s", implant.OS)
	}
	if implant.Size == 0 {
		t.Error("expected non-zero size")
	}
	if implant.Checksum == "" {
		t.Error("expected non-empty checksum")
	}

	if implant.Data[0] != 0x4D || implant.Data[1] != 0x5A {
		t.Error("expected MZ header for PE")
	}
}

func TestGenerateLinux(t *testing.T) {
	engine := NewImplantEngine(nil)
	params := &GenerateParams{
		Name: "test-linux",
		Arch: ArchX64,
		OS:   OSLinux,
	}

	implant, err := engine.Generate(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if implant.Data[0] != 0x7F || implant.Data[1] != 'E' || implant.Data[2] != 'L' || implant.Data[3] != 'F' {
		t.Error("expected ELF header")
	}
}

func TestGenerateDarwin(t *testing.T) {
	engine := NewImplantEngine(nil)
	params := &GenerateParams{
		Name: "test-darwin",
		Arch: ArchX64,
		OS:   OSDarwin,
	}

	implant, err := engine.Generate(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if implant.OS != OSDarwin {
		t.Errorf("expected os darwin, got %s", implant.OS)
	}
}

func TestGenerateWithEncryption(t *testing.T) {
	engine := NewImplantEngine(nil)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	params := &GenerateParams{
		Name:    "encrypted-implant",
		Arch:    ArchX64,
		OS:      OSWindows,
		Encrypt: true,
		Key:     key,
	}

	implant, err := engine.Generate(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !implant.Encrypted {
		t.Error("expected encrypted implant")
	}
}

func TestGenerateWithoutName(t *testing.T) {
	engine := NewImplantEngine(nil)
	params := &GenerateParams{
		Arch: ArchX64,
		OS:   OSWindows,
	}

	_, err := engine.Generate(params)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestEncryptDecryptPayload(t *testing.T) {
	engine := NewImplantEngine(nil)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	original := []byte("hello world implant data")

	encrypted, err := engine.EncryptPayload(original, key)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	if bytes.Equal(encrypted, original) {
		t.Error("encrypted data should differ from original")
	}

	decrypted, err := engine.DecryptPayload(encrypted, key)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Error("decrypted data should match original")
	}
}

func TestEncryptPayloadWrongKey(t *testing.T) {
	engine := NewImplantEngine(nil)
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1

	original := []byte("secret data")

	encrypted, err := engine.EncryptPayload(original, key1)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	_, err = engine.DecryptPayload(encrypted, key2)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestTemplates(t *testing.T) {
	engine := NewImplantEngine(nil)

	info := TemplateInfo{
		Name: "test-template",
		Arch: ArchX64,
		OS:   OSWindows,
		Size: 1024,
	}
	data := []byte("template data")

	engine.AddTemplate("test-template", info, data)

	gotInfo, gotData, ok := engine.GetTemplate("test-template")
	if !ok {
		t.Fatal("expected template to exist")
	}
	if gotInfo.Name != "test-template" {
		t.Errorf("expected name test-template, got %s", gotInfo.Name)
	}
	if !bytes.Equal(gotData, data) {
		t.Error("template data mismatch")
	}

	templates := engine.ListTemplates()
	if len(templates) != 1 {
		t.Errorf("expected 1 template, got %d", len(templates))
	}

	_, _, ok = engine.GetTemplate("nonexistent")
	if ok {
		t.Error("expected template not to exist")
	}
}

func TestPayloadEncryptor(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	pe := NewPayloadEncryptor(key)
	if pe == nil {
		t.Fatal("expected non-nil encryptor")
	}

	data := []byte("payload data")
	encrypted, err := pe.Encrypt(data)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	decrypted, err := pe.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}

	if !bytes.Equal(decrypted, data) {
		t.Error("decrypted data mismatch")
	}
}

func TestTemplateManager(t *testing.T) {
	tm := NewTemplateManager()
	if tm == nil {
		t.Fatal("expected non-nil template manager")
	}

	if tm.Count() != 0 {
		t.Errorf("expected 0 templates, got %d", tm.Count())
	}

	info := TemplateInfo{Name: "tmpl1", Arch: ArchX64, OS: OSWindows, Size: 100}
	tm.Add("tmpl1", info, []byte("data1"))

	if tm.Count() != 1 {
		t.Errorf("expected 1 template, got %d", tm.Count())
	}

	gotInfo, _, ok := tm.Get("tmpl1")
	if !ok || gotInfo.Name != "tmpl1" {
		t.Error("failed to get template")
	}

	err := tm.Remove("tmpl1")
	if err != nil {
		t.Fatalf("remove error: %v", err)
	}

	if tm.Count() != 0 {
		t.Errorf("expected 0 templates after remove, got %d", tm.Count())
	}

	err = tm.Remove("nonexistent")
	if err == nil {
		t.Error("expected error removing nonexistent template")
	}
}

func TestGenerateWithConfig(t *testing.T) {
	engine := NewImplantEngine(nil)
	config := &BeaconConfig{
		ID:           "beacon-123",
		CallbackURLs: []string{"https://c2.example.com/beacon"},
		SleepTime:    30 * time.Second,
		Jitter:       0.15,
		MaxRetries:   5,
		NoiseLevel:   2,
	}

	params := &GenerateParams{
		Name:   "config-implant",
		Arch:   ArchX64,
		OS:     OSWindows,
		Config: config,
	}

	implant, err := engine.Generate(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if implant.Size == 0 {
		t.Error("expected non-zero size with config")
	}
}

func TestGenerateARM64(t *testing.T) {
	engine := NewImplantEngine(nil)
	params := &GenerateParams{
		Name: "arm64-implant",
		Arch: ArchARM64,
		OS:   OSWindows,
	}

	implant, err := engine.Generate(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if implant.Arch != ArchARM64 {
		t.Errorf("expected arch arm64, got %s", implant.Arch)
	}
}

func TestSetGetConfig(t *testing.T) {
	engine := NewImplantEngine(nil)
	newConfig := &GeneratorConfig{
		DefaultArch:      ArchX86,
		DefaultOS:        OSLinux,
		MaxBinarySize:    2048,
		EnableEncryption: false,
		ObfuscationLevel: 0,
	}

	engine.SetConfig(newConfig)
	got := engine.GetConfig()

	if got.DefaultArch != ArchX86 {
		t.Errorf("expected arch x86, got %s", got.DefaultArch)
	}
	if got.DefaultOS != OSLinux {
		t.Errorf("expected os linux, got %s", got.DefaultOS)
	}
}

func TestImplantMetadata(t *testing.T) {
	engine := NewImplantEngine(nil)
	metadata := map[string]string{
		"team":   "red",
		"env":    "test",
		"author": "ops",
	}

	params := &GenerateParams{
		Name:     "meta-implant",
		Arch:     ArchX64,
		OS:       OSWindows,
		Metadata: metadata,
	}

	implant, err := engine.Generate(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if implant.Metadata["team"] != "red" {
		t.Error("expected metadata team=red")
	}
	if implant.Metadata["env"] != "test" {
		t.Error("expected metadata env=test")
	}
}

func TestImplantTimestamp(t *testing.T) {
	engine := NewImplantEngine(nil)
	before := time.Now()

	params := &GenerateParams{
		Name: "ts-implant",
		Arch: ArchX64,
		OS:   OSWindows,
	}

	implant, err := engine.Generate(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	after := time.Now()

	if implant.CreatedAt.Before(before) || implant.CreatedAt.After(after) {
		t.Error("implant CreatedAt not within expected time range")
	}
}

func TestDefaultConfigs(t *testing.T) {
	config := NewDefaultGeneratorConfig()
	if config == nil {
		t.Fatal("expected non-nil default config")
	}
	if config.DefaultArch != ArchX64 {
		t.Error("expected default arch x64")
	}

	bc := NewDefaultBeaconConfig()
	if bc == nil {
		t.Fatal("expected non-nil default beacon config")
	}
	if bc.SleepTime != 60*time.Second {
		t.Error("expected default sleep time 60s")
	}
	if bc.Jitter != 0.2 {
		t.Error("expected default jitter 0.2")
	}
}
