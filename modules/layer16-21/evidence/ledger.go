package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type EvidenceLedger struct {
	mu      sync.RWMutex
	entries []*EvidenceEntry
	path    string
}

func NewEvidenceLedger(dbPath string) *EvidenceLedger {
	ledger := &EvidenceLedger{
		entries: make([]*EvidenceEntry, 0),
		path:    dbPath,
	}
	ledger.load()
	return ledger
}

func (el *EvidenceLedger) AddEntry(entry *EvidenceEntry) error {
	el.mu.Lock()
	defer el.mu.Unlock()

	if entry.ID == "" {
		return fmt.Errorf("entry ID is required")
	}

	entry.Timestamp = time.Now().UTC()

	if len(el.entries) > 0 {
		entry.PrevHash = el.entries[len(el.entries)-1].Hash
	} else {
		entry.PrevHash = ""
	}

	entry.Hash = el.computeHash(entry)

	el.entries = append(el.entries, entry)
	return el.persist()
}

func (el *EvidenceLedger) GetEntry(id string) (*EvidenceEntry, error) {
	el.mu.RLock()
	defer el.mu.RUnlock()

	for _, e := range el.entries {
		if e.ID == id {
			return e, nil
		}
	}
	return nil, fmt.Errorf("entry not found: %s", id)
}

func (el *EvidenceLedger) VerifyChain() (bool, error) {
	el.mu.RLock()
	defer el.mu.RUnlock()

	for i, entry := range el.entries {
		if entry.Hash != el.computeHash(entry) {
			return false, fmt.Errorf("hash mismatch at index %d", i)
		}
		if i > 0 && entry.PrevHash != el.entries[i-1].Hash {
			return false, fmt.Errorf("chain break at index %d", i)
		}
	}
	return true, nil
}

func (el *EvidenceLedger) GetAll() []*EvidenceEntry {
	el.mu.RLock()
	defer el.mu.RUnlock()

	result := make([]*EvidenceEntry, len(el.entries))
	copy(result, el.entries)
	return result
}

func (el *EvidenceLedger) computeHash(entry *EvidenceEntry) string {
	data := fmt.Sprintf("%s%s%s%x", entry.ID, entry.PrevHash, entry.Timestamp.Format(time.RFC3339Nano), entry.Data)
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h)
}

func (el *EvidenceLedger) load() {
	data, err := os.ReadFile(el.path)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &el.entries)
}

func (el *EvidenceLedger) persist() error {
	data, err := json.Marshal(el.entries)
	if err != nil {
		return err
	}
	return os.WriteFile(el.path, data, 0600)
}
