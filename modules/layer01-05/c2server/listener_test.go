package c2server

import (
	"testing"

	"github.com/angel-platform/angel/pkg/eventbus"
	"github.com/angel-platform/angel/pkg/logger"
	"github.com/angel-platform/angel/pkg/types"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.BindAddr != "0.0.0.0" {
		t.Errorf("Expected bind addr 0.0.0.0, got %s", config.BindAddr)
	}
	if config.BindPort != 8443 {
		t.Errorf("Expected bind port 8443, got %d", config.BindPort)
	}
	if config.MaxAgents != 100 {
		t.Errorf("Expected max agents 100, got %d", config.MaxAgents)
	}
}

func TestConfigValidation(t *testing.T) {
	config := DefaultConfig()
	if err := config.Validate(); err != nil {
		t.Errorf("Default config should be valid: %v", err)
	}
	config.BindAddr = ""
	if err := config.Validate(); err == nil {
		t.Error("Expected error for empty bind addr")
	}
	config = DefaultConfig()
	config.BindPort = 0
	if err := config.Validate(); err == nil {
		t.Error("Expected error for invalid port")
	}
	config = DefaultConfig()
	config.CryptoKey = ""
	if err := config.Validate(); err == nil {
		t.Error("Expected error for empty crypto key")
	}
	config = DefaultConfig()
	config.MaxAgents = 0
	if err := config.Validate(); err == nil {
		t.Error("Expected error for zero max agents")
	}
	config = DefaultConfig()
	config.DBPath = ""
	if err := config.Validate(); err == nil {
		t.Error("Expected error for empty db path")
	}
}

func TestNewServerCrypto(t *testing.T) {
	crypto, err := NewServerCrypto()
	if err != nil {
		t.Fatalf("Failed to create server crypto: %v", err)
	}
	if crypto.PublicKey() == nil {
		t.Error("Expected public key to be set")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	crypto, err := NewServerCrypto()
	if err != nil {
		t.Fatalf("Failed to create server crypto: %v", err)
	}
	plaintext := []byte("hello world")
	encrypted, err := crypto.EncryptPayload(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	decrypted, err := crypto.DecryptPayload(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match: got %s, want %s", decrypted, plaintext)
	}
}

func TestSignVerify(t *testing.T) {
	crypto, err := NewServerCrypto()
	if err != nil {
		t.Fatalf("Failed to create server crypto: %v", err)
	}
	data := []byte("test data")
	sig, err := crypto.SignData(data)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}
	if !crypto.VerifySignature(data, sig) {
		t.Error("Expected valid signature")
	}
	if crypto.VerifySignature([]byte("wrong data"), sig) {
		t.Error("Expected invalid signature")
	}
}

func TestTaskQueueEnqueueDequeue(t *testing.T) {
	q := NewTaskQueue()
	task := &types.Task{
		ID:      "task-1",
		Type:    types.TaskTypeShell,
		Payload: []byte("ls -la"),
	}
	if err := q.Enqueue("agent-1", task); err != nil {
		t.Fatalf("Failed to enqueue: %v", err)
	}
	if q.GetPendingCount("agent-1") != 1 {
		t.Errorf("Expected 1 pending task, got %d", q.GetPendingCount("agent-1"))
	}
	dequeued, ok := q.Dequeue("agent-1")
	if !ok {
		t.Fatal("Failed to dequeue")
	}
	if dequeued.ID != "task-1" {
		t.Errorf("Expected task-1, got %s", dequeued.ID)
	}
	if q.GetPendingCount("agent-1") != 0 {
		t.Errorf("Expected 0 pending tasks, got %d", q.GetPendingCount("agent-1"))
	}
}

func TestTaskQueuePeek(t *testing.T) {
	q := NewTaskQueue()
	task := &types.Task{
		ID:   "task-1",
		Type: types.TaskTypeShell,
	}
	q.Enqueue("agent-1", task)
	peeked, ok := q.Peek("agent-1")
	if !ok {
		t.Fatal("Failed to peek")
	}
	if peeked.ID != "task-1" {
		t.Errorf("Expected task-1, got %s", peeked.ID)
	}
	if q.GetPendingCount("agent-1") != 1 {
		t.Errorf("Expected 1 pending task after peek, got %d", q.GetPendingCount("agent-1"))
	}
}

func TestTaskQueueMarkComplete(t *testing.T) {
	q := NewTaskQueue()
	task := &types.Task{
		ID:   "task-1",
		Type: types.TaskTypeShell,
	}
	q.Enqueue("agent-1", task)
	if err := q.MarkComplete("task-1"); err != nil {
		t.Fatalf("Failed to mark complete: %v", err)
	}
	if q.GetPendingCount("agent-1") != 0 {
		t.Errorf("Expected 0 pending tasks after complete, got %d", q.GetPendingCount("agent-1"))
	}
}

func TestTaskQueueMarkFailed(t *testing.T) {
	q := NewTaskQueue()
	task := &types.Task{
		ID:   "task-1",
		Type: types.TaskTypeShell,
	}
	q.Enqueue("agent-1", task)
	if err := q.MarkFailed("task-1", nil); err != nil {
		t.Fatalf("Failed to mark failed: %v", err)
	}
	if q.GetPendingCount("agent-1") != 0 {
		t.Errorf("Expected 0 pending tasks after failed, got %d", q.GetPendingCount("agent-1"))
	}
}

func TestListenerManager(t *testing.T) {
	log := logger.New("test", logger.LevelInfo)
	mgr := NewListenerManager(log)
	if len(mgr.GetAll()) != 0 {
		t.Errorf("Expected 0 listeners, got %d", len(mgr.GetAll()))
	}
	crypto, err := NewServerCrypto()
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}
	eb := eventbus.New("test-key")
	httpListener := NewHTTPListener("127.0.0.1", 9999, crypto, eb, log)
	mgr.Add(httpListener)
	if len(mgr.GetAll()) != 1 {
		t.Errorf("Expected 1 listener, got %d", len(mgr.GetAll()))
	}
	httpListeners := mgr.GetByType("http")
	if len(httpListeners) != 1 {
		t.Errorf("Expected 1 http listener, got %d", len(httpListeners))
	}
	dnsListeners := mgr.GetByType("dns")
	if len(dnsListeners) != 0 {
		t.Errorf("Expected 0 dns listeners, got %d", len(dnsListeners))
	}
}

func TestHTTPListenerStartStop(t *testing.T) {
	log := logger.New("test", logger.LevelInfo)
	crypto, err := NewServerCrypto()
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}
	eb := eventbus.New("test-key")
	defer eb.Stop()
	httpListener := NewHTTPListener("127.0.0.1", 9998, crypto, eb, log)
	if httpListener.Status() != "stopped" {
		t.Errorf("Expected status stopped, got %s", httpListener.Status())
	}
	if httpListener.Type() != "http" {
		t.Errorf("Expected type http, got %s", httpListener.Type())
	}
}

func TestDNSListenerStartStop(t *testing.T) {
	log := logger.New("test", logger.LevelInfo)
	crypto, err := NewServerCrypto()
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}
	eb := eventbus.New("test-key")
	defer eb.Stop()
	dnsListener := NewDNSListener("127.0.0.1", 9997, crypto, eb, log)
	if dnsListener.Status() != "stopped" {
		t.Errorf("Expected status stopped, got %s", dnsListener.Status())
	}
	if dnsListener.Type() != "dns" {
		t.Errorf("Expected type dns, got %s", dnsListener.Type())
	}
}

func TestWSSListenerStartStop(t *testing.T) {
	log := logger.New("test", logger.LevelInfo)
	crypto, err := NewServerCrypto()
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}
	eb := eventbus.New("test-key")
	defer eb.Stop()
	wssListener := NewWSSListener("127.0.0.1", 9996, crypto, eb, log)
	if wssListener.Status() != "stopped" {
		t.Errorf("Expected status stopped, got %s", wssListener.Status())
	}
	if wssListener.Type() != "wss" {
		t.Errorf("Expected type wss, got %s", wssListener.Type())
	}
}
