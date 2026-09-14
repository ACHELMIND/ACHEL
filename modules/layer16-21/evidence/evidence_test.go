package evidence

import (
	"path/filepath"
	"testing"
)

func TestEvidenceLedgerAddAndGet(t *testing.T) {
	dir := t.TempDir()
	ledger := NewEvidenceLedger(filepath.Join(dir, "test.json"))

	entry := &EvidenceEntry{
		ID:   "test-001",
		Data: []byte("test evidence data"),
	}

	if err := ledger.AddEntry(entry); err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}

	got, err := ledger.GetEntry("test-001")
	if err != nil {
		t.Fatalf("GetEntry failed: %v", err)
	}

	if got.Hash == "" {
		t.Error("Expected hash to be computed")
	}
	if got.PrevHash != "" {
		t.Error("Expected first entry to have empty PrevHash")
	}
}

func TestEvidenceLedgerChain(t *testing.T) {
	dir := t.TempDir()
	ledger := NewEvidenceLedger(filepath.Join(dir, "test.json"))

	for i := 0; i < 5; i++ {
		entry := &EvidenceEntry{
			ID:   "entry-" + string(rune('0'+i)),
			Data: []byte("data"),
		}
		if err := ledger.AddEntry(entry); err != nil {
			t.Fatalf("AddEntry %d failed: %v", i, err)
		}
	}

	valid, err := ledger.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !valid {
		t.Error("Expected chain to be valid")
	}

	all := ledger.GetAll()
	if len(all) != 5 {
		t.Errorf("Expected 5 entries, got %d", len(all))
	}

	if all[1].PrevHash != all[0].Hash {
		t.Error("Expected PrevHash of second entry to equal Hash of first")
	}
}

func TestEvidenceLedgerVerifyChainIntegrity(t *testing.T) {
	dir := t.TempDir()
	ledger := NewEvidenceLedger(filepath.Join(dir, "test.json"))

	for i := 0; i < 3; i++ {
		entry := &EvidenceEntry{
			ID:   "entry-" + string(rune('0'+i)),
			Data: []byte("data"),
		}
		if err := ledger.AddEntry(entry); err != nil {
			t.Fatalf("AddEntry %d failed: %v", i, err)
		}

		// Recompute hash for validation
		entry.Hash = ledger.computeHash(entry)
	}

	valid, err := ledger.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !valid {
		t.Error("Expected chain to be valid")
	}
}

func TestEvidenceCollectorDiff(t *testing.T) {
	collector := NewEvidenceCollector()

	capture, err := collector.CaptureDiff("old content", "new content")
	if err != nil {
		t.Fatalf("CaptureDiff failed: %v", err)
	}

	if capture.Type != "diff" {
		t.Errorf("Expected type 'diff', got '%s'", capture.Type)
	}
	if capture.Hash == "" {
		t.Error("Expected hash to be set")
	}
}

func TestRedactorPII(t *testing.T) {
	redactor := NewRedactor()

	input := []byte("Contact john@example.com or call 555-123-4567")
	result := redactor.RedactPII(input)

	if contains(string(result), "john@example.com") {
		t.Error("Expected email to be redacted")
	}
	if contains(string(result), "555-123-4567") {
		t.Error("Expected phone to be redacted")
	}
}

func TestRedactorSecrets(t *testing.T) {
	redactor := NewRedactor()

	input := []byte(`api_key="supersecretkey12345678901234567890"`)
	result := redactor.RedactSecrets(input)

	if contains(string(result), "supersecretkey12345678901234567890") {
		t.Error("Expected secret to be redacted")
	}
}

func TestRedactorCerts(t *testing.T) {
	redactor := NewRedactor()

	input := []byte("key: -----BEGIN PRIVATE KEY-----\nMIIBIjANBgkq...\n-----END PRIVATE KEY-----")
	result := redactor.RedactCerts(input)

	if contains(string(result), "BEGIN PRIVATE KEY") {
		t.Error("Expected certificate to be redacted")
	}
}

func TestEvidenceStorageLocal(t *testing.T) {
	dir := t.TempDir()
	storage := NewEvidenceStorage(dir)

	evidence := &EvidenceCapture{
		ID:   "test-001",
		Type: "local_test",
		Data: []byte("test data"),
	}

	if err := storage.StoreLocal("evidence/test.json", evidence); err != nil {
		t.Fatalf("StoreLocal failed: %v", err)
	}

	loaded, err := storage.Load("evidence/test.json")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.ID != evidence.ID {
		t.Errorf("Expected ID '%s', got '%s'", evidence.ID, loaded.ID)
	}
}

func TestEvidenceStorageEncrypted(t *testing.T) {
	dir := t.TempDir()
	storage := NewEvidenceStorage(dir)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	evidence := &EvidenceCapture{
		ID:   "test-enc-001",
		Type: "encrypted_test",
		Data: []byte("secret data"),
	}

	if err := storage.StoreEncrypted("encrypted/test.enc", key, evidence); err != nil {
		t.Fatalf("StoreEncrypted failed: %v", err)
	}

	loaded, err := storage.LoadEncrypted("encrypted/test.enc", key)
	if err != nil {
		t.Fatalf("LoadEncrypted failed: %v", err)
	}

	if loaded.ID != evidence.ID {
		t.Errorf("Expected ID '%s', got '%s'", evidence.ID, loaded.ID)
	}
}

func TestEvidenceLedgerMissingID(t *testing.T) {
	dir := t.TempDir()
	ledger := NewEvidenceLedger(filepath.Join(dir, "test.json"))

	entry := &EvidenceEntry{
		Data: []byte("data"),
	}

	if err := ledger.AddEntry(entry); err == nil {
		t.Error("Expected error for missing ID")
	}
}

func TestEvidenceLedgerGetNotFound(t *testing.T) {
	dir := t.TempDir()
	ledger := NewEvidenceLedger(filepath.Join(dir, "test.json"))

	_, err := ledger.GetEntry("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent entry")
	}
}

func TestEvidenceLedgerPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "persist.json")

	l1 := NewEvidenceLedger(path)
	l1.AddEntry(&EvidenceEntry{ID: "persist-001", Data: []byte("data")})

	l2 := NewEvidenceLedger(path)
	got, err := l2.GetEntry("persist-001")
	if err != nil {
		t.Fatalf("Expected entry to persist: %v", err)
	}
	if got.ID != "persist-001" {
		t.Errorf("Expected ID 'persist-001', got '%s'", got.ID)
	}
}

func TestEvidenceCollectorCaptureDiffContent(t *testing.T) {
	collector := NewEvidenceCollector()

	capture, err := collector.CaptureDiff("old", "new")
	if err != nil {
		t.Fatalf("CaptureDiff failed: %v", err)
	}

	if !contains(string(capture.Data), "--- OLD:") {
		t.Error("Expected diff to contain OLD marker")
	}
	if !contains(string(capture.Data), "+++ NEW:") {
		t.Error("Expected diff to contain NEW marker")
	}
}

func TestRedactorAllCombined(t *testing.T) {
	redactor := NewRedactor()

	input := []byte("user: admin@test.com pass: secretPass123 key: -----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----")

	result := redactor.RedactPII(input)
	result = redactor.RedactSecrets(result)
	result = redactor.RedactCerts(result)

	if contains(string(result), "admin@test.com") {
		t.Error("Email should be redacted")
	}
	if contains(string(result), "BEGIN PRIVATE KEY") {
		t.Error("Certificate should be redacted")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}


