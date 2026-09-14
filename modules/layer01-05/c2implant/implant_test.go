package c2implant

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	angelcrypto "github.com/angel-platform/angel/pkg/crypto"
	"github.com/angel-platform/angel/pkg/types"
)

func TestNewImplant(t *testing.T) {
	config := DefaultConfig()
	implant := NewImplant(config)

	if implant == nil {
		t.Fatal("NewImplant returned nil")
	}

	if implant.GetID() == "" {
		t.Error("implant ID should not be empty")
	}

	if implant.GetState() != StateIdle {
		t.Errorf("expected state Idle, got %s", implant.GetState())
	}

	if implant.IsRunning() {
		t.Error("implant should not be running initially")
	}
}

func TestNewImplantDefaultConfig(t *testing.T) {
	implant := NewImplant(nil)

	if implant == nil {
		t.Fatal("NewImplant with nil config returned nil")
	}

	cfg := implant.GetConfig()
	if cfg.ServerURL != "https://teamserver.local:8443" {
		t.Errorf("unexpected default server URL: %s", cfg.ServerURL)
	}

	if cfg.SleepTime != 30*time.Second {
		t.Errorf("unexpected default sleep time: %v", cfg.SleepTime)
	}
}

func TestImplantConfig(t *testing.T) {
	cfg := DefaultConfig()

	if err := cfg.Validate(); err != nil {
		t.Errorf("default config should be valid: %v", err)
	}

	cfg.ServerURL = ""
	if err := cfg.Validate(); err == nil {
		t.Error("empty server URL should fail validation")
	}

	cfg = DefaultConfig()
	cfg.SleepTime = 0
	if err := cfg.Validate(); err == nil {
		t.Error("zero sleep time should fail validation")
	}

	cfg = DefaultConfig()
	cfg.Jitter = 1.5
	if err := cfg.Validate(); err == nil {
		t.Error("jitter > 1.0 should fail validation")
	}

	cfg = DefaultConfig()
	cfg.MaxRetries = 0
	if err := cfg.Validate(); err == nil {
		t.Error("zero max retries should fail validation")
	}
}

func TestImplantConfigJSON(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ImplantID = "test-123"

	data, err := cfg.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	loaded, err := LoadConfig(data)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.ImplantID != "test-123" {
		t.Errorf("expected implant ID test-123, got %s", loaded.ImplantID)
	}
}

func TestImplantConfigExpired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.KillDate = time.Now().Add(-1 * time.Hour)

	if !cfg.IsExpired() {
		t.Error("config with past kill date should be expired")
	}

	cfg = DefaultConfig()
	cfg.KillDate = time.Now().Add(1 * time.Hour)

	if cfg.IsExpired() {
		t.Error("config with future kill date should not be expired")
	}

	cfg = DefaultConfig()
	cfg.KillDate = time.Time{}

	if cfg.IsExpired() {
		t.Error("config with zero kill date should not be expired")
	}
}

func TestCryptoEncryptDecrypt(t *testing.T) {
	localKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate local key failed: %v", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key failed: %v", err)
	}

	serverPubBytes := elliptic.MarshalCompressed(serverKey.PublicKey.Curve, serverKey.PublicKey.X, serverKey.PublicKey.Y)

	cryptoImpl, err := NewImplantCrypto(serverPubBytes)
	if err != nil {
		t.Fatalf("NewImplantCrypto failed: %v", err)
	}

	_, err = cryptoImpl.KeyExchange(localKey, serverPubBytes)
	if err != nil {
		t.Fatalf("KeyExchange failed: %v", err)
	}

	if !cryptoImpl.IsEstablished() {
		t.Error("session should be established")
	}

	plaintext := []byte("hello world")
	encrypted, err := cryptoImpl.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := cryptoImpl.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted text doesn't match: got %s, want %s", decrypted, plaintext)
	}
}

func generateTestECDHKey() ([]byte, error) {
	key, err := angelcrypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, err
	}
	return key.PublicKey, nil
}

func TestCryptoKeyExchange(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	crypto1, err := NewImplantCrypto(key)
	if err != nil {
		t.Fatalf("NewImplantCrypto 1 failed: %v", err)
	}

	crypto2, err := NewImplantCrypto(key)
	if err != nil {
		t.Fatalf("NewImplantCrypto 2 failed: %v", err)
	}

	shared1, err := crypto1.KeyExchange(crypto1.localKey, crypto2.GetLocalPublicKeyRaw())
	if err != nil {
		t.Fatalf("KeyExchange 1 failed: %v", err)
	}

	shared2, err := crypto2.KeyExchange(crypto2.localKey, crypto1.GetLocalPublicKeyRaw())
	if err != nil {
		t.Fatalf("KeyExchange 2 failed: %v", err)
	}

	if string(shared1) != string(shared2) {
		t.Error("shared secrets don't match")
	}
}

func TestTaskDispatcher(t *testing.T) {
	dispatcher := NewTaskDispatcher()

	if !dispatcher.HasHandler(types.TaskTypeShell) {
		t.Error("dispatcher should have shell handler")
	}

	if !dispatcher.HasHandler(types.TaskTypeDownload) {
		t.Error("dispatcher should have download handler")
	}

	if !dispatcher.HasHandler(types.TaskTypeUpload) {
		t.Error("dispatcher should have upload handler")
	}

	if !dispatcher.HasHandler(types.TaskTypeExecute) {
		t.Error("dispatcher should have execute handler")
	}

	if dispatcher.HasHandler("nonexistent") {
		t.Error("dispatcher should not have nonexistent handler")
	}
}

func TestTaskDispatcherDispatch(t *testing.T) {
	dispatcher := NewTaskDispatcher()

	task := &types.Task{
		ID:      "test-task-1",
		AgentID: "test-agent",
		Type:    types.TaskTypeShell,
		Payload: []byte("echo hello"),
		Status:  types.TaskStatusPending,
	}

	result, err := dispatcher.Dispatch(task)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if result == nil {
		t.Fatal("Dispatch returned nil result")
	}

	if !result.Success {
		t.Errorf("shell task should succeed: %s", result.Error)
	}
}

func TestTaskDispatcherCustomHandler(t *testing.T) {
	dispatcher := NewTaskDispatcher()

	customCalled := false
	dispatcher.RegisterHandler("custom", func(task *types.Task) (*types.TaskResult, error) {
		customCalled = true
		return &types.TaskResult{
			Module:    "custom",
			Success:   true,
			Data:      make(map[string]interface{}),
			Timestamp: time.Now(),
		}, nil
	})

	task := &types.Task{
		ID:      "custom-task",
		Type:    "custom",
		Payload: []byte("test"),
	}

	_, err := dispatcher.Dispatch(task)
	if err != nil {
		t.Fatalf("Dispatch custom failed: %v", err)
	}

	if !customCalled {
		t.Error("custom handler was not called")
	}
}

func TestTaskDispatcherUnknownType(t *testing.T) {
	dispatcher := NewTaskDispatcher()

	task := &types.Task{
		ID:      "unknown-task",
		Type:    "unknown",
		Payload: []byte("test"),
	}

	result, err := dispatcher.Dispatch(task)
	if err != nil {
		t.Fatalf("Dispatch should not error for unknown type: %v", err)
	}

	if result.Success {
		t.Error("unknown task type should not succeed")
	}
}

func TestSleepController(t *testing.T) {
	sc := NewSleepController(100*time.Millisecond, 0.1)

	start := time.Now()
	actual := sc.Sleep(50*time.Millisecond, 0.1)
	elapsed := time.Since(start)

	if elapsed < 40*time.Millisecond {
		t.Errorf("sleep was too short: %v", elapsed)
	}

	if actual < 10*time.Millisecond {
		t.Errorf("actual sleep duration too short: %v", actual)
	}

	totalSleep, count := sc.GetStats()
	if count != 1 {
		t.Errorf("expected 1 sleep, got %d", count)
	}

	if totalSleep < 10*time.Millisecond {
		t.Errorf("total sleep too short: %v", totalSleep)
	}
}

func TestSleepControllerJitter(t *testing.T) {
	base := 100 * time.Millisecond
	jitter := 0.5

	samples := make([]time.Duration, 100)
	for i := range samples {
		samples[i] = JitterDuration(base, jitter)
	}

	minDuration := base
	maxDuration := base
	for _, s := range samples {
		if s < minDuration {
			minDuration = s
		}
		if s > maxDuration {
			maxDuration = s
		}
	}

	if minDuration >= base {
		t.Error("min duration should be less than base with positive jitter")
	}

	if maxDuration <= base {
		t.Error("max duration should be greater than base with positive jitter")
	}
}

func TestSleepControllerZeroJitter(t *testing.T) {
	base := 100 * time.Millisecond
	result := JitterDuration(base, 0)

	if result != base {
		t.Errorf("zero jitter should return base duration, got %v", result)
	}
}

func TestSleepControllerSetters(t *testing.T) {
	sc := NewSleepController(100*time.Millisecond, 0.1)

	sc.SetBaseSleep(200 * time.Millisecond)
	if sc.GetBaseSleep() != 200*time.Millisecond {
		t.Errorf("expected 200ms, got %v", sc.GetBaseSleep())
	}

	sc.SetJitter(0.5)
	if sc.GetJitter() != 0.5 {
		t.Errorf("expected 0.5, got %v", sc.GetJitter())
	}

	sc.SetBaseSleep(0)
	if sc.GetBaseSleep() != 200*time.Millisecond {
		t.Error("should not accept zero base sleep")
	}

	sc.SetJitter(-0.1)
	if sc.GetJitter() != 0.5 {
		t.Error("should not accept negative jitter")
	}

	sc.SetJitter(1.5)
	if sc.GetJitter() != 0.5 {
		t.Error("should not accept jitter > 1.0")
	}
}

func TestImplantRunShutdown(t *testing.T) {
	config := DefaultConfig()
	config.SleepTime = 10 * time.Millisecond
	implant := NewImplant(config)

	done := make(chan error, 1)
	go func() {
		done <- implant.Run()
	}()

	time.Sleep(100 * time.Millisecond)

	implant.Shutdown()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("implant run returned (expected): %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("implant did not shutdown in time")
	}

	if implant.IsRunning() {
		t.Error("implant should not be running after shutdown")
	}

	if implant.GetState() != StateShutdown {
		t.Errorf("expected state Shutdown, got %s", implant.GetState())
	}
}

func TestImplantRegisterTaskHandler(t *testing.T) {
	config := DefaultConfig()
	implant := NewImplant(config)

	customCalled := false
	implant.RegisterTaskHandler("custom", func(task *types.Task) (*types.TaskResult, error) {
		customCalled = true
		return &types.TaskResult{
			Module:    "custom",
			Success:   true,
			Data:      make(map[string]interface{}),
			Timestamp: time.Now(),
		}, nil
	})

	if !implant.GetDispatcher().HasHandler("custom") {
		t.Error("custom handler should be registered")
	}

	task := &types.Task{
		ID:      "custom-task",
		Type:    "custom",
		Payload: []byte("test"),
	}

	_, err := implant.ExecuteTask(task)
	if err != nil {
		t.Fatalf("ExecuteTask failed: %v", err)
	}

	if !customCalled {
		t.Error("custom handler was not called")
	}
}

func TestLoadConfigEmpty(t *testing.T) {
	_, err := LoadConfig([]byte{})
	if err == nil {
		t.Error("LoadConfig with empty data should fail")
	}

	_, err = LoadConfig(nil)
	if err == nil {
		t.Error("LoadConfig with nil data should fail")
	}
}

func TestLoadConfigInvalid(t *testing.T) {
	_, err := LoadConfig([]byte("not json"))
	if err == nil {
		t.Error("LoadConfig with invalid JSON should fail")
	}
}

func TestImplantCryptoSign(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	crypto, err := NewImplantCrypto(key)
	if err != nil {
		t.Fatalf("NewImplantCrypto failed: %v", err)
	}

	data := []byte("message to sign")
	sig, err := crypto.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("signature should not be empty")
	}
}

func TestImplantCryptoHMAC(t *testing.T) {
	localKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate local key failed: %v", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key failed: %v", err)
	}

	serverPubBytes := elliptic.MarshalCompressed(serverKey.PublicKey.Curve, serverKey.PublicKey.X, serverKey.PublicKey.Y)

	cryptoImpl, err := NewImplantCrypto(serverPubBytes)
	if err != nil {
		t.Fatalf("NewImplantCrypto failed: %v", err)
	}

	_, err = cryptoImpl.KeyExchange(localKey, serverPubBytes)
	if err != nil {
		t.Fatalf("KeyExchange failed: %v", err)
	}

	data := []byte("data to authenticate")
	hmac1 := cryptoImpl.HMAC(data)
	hmac2 := cryptoImpl.HMAC(data)

	if len(hmac1) == 0 {
		t.Error("HMAC should not be empty")
	}

	if string(hmac1) != string(hmac2) {
		t.Error("HMAC should be deterministic")
	}
}

func TestShellTaskHandler(t *testing.T) {
	task := &types.Task{
		ID:      "shell-test",
		Type:    types.TaskTypeShell,
		Payload: []byte("echo test123"),
	}

	result, err := ShellTaskHandler(task)
	if err != nil {
		t.Fatalf("ShellTaskHandler failed: %v", err)
	}

	if !result.Success {
		t.Errorf("shell task should succeed: %s", result.Error)
	}

	if stdout, ok := result.Data["stdout"].(string); ok {
		if stdout != "test123\n" {
			t.Errorf("unexpected stdout: %q", stdout)
		}
	}
}

func TestShellTaskHandlerEmptyPayload(t *testing.T) {
	task := &types.Task{
		ID:      "shell-empty",
		Type:    types.TaskTypeShell,
		Payload: []byte{},
	}

	result, err := ShellTaskHandler(task)
	if err != nil {
		t.Fatalf("ShellTaskHandler failed: %v", err)
	}

	if result.Success {
		t.Error("shell task with empty payload should fail")
	}
}
