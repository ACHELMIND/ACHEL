package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/angel-platform/angel/pkg/crypto"
)

type EvidenceStorage struct {
	basePath string
}

func NewEvidenceStorage(basePath string) *EvidenceStorage {
	return &EvidenceStorage{basePath: basePath}
}

func (es *EvidenceStorage) StoreLocal(path string, evidence *EvidenceCapture) error {
	fullPath := filepath.Join(es.basePath, path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	data, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}

	return os.WriteFile(fullPath, data, 0600)
}

func (es *EvidenceStorage) StoreEncrypted(path string, key []byte, evidence *EvidenceCapture) error {
	data, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}

	encrypted, err := crypto.EncryptAESGCM(key, data)
	if err != nil {
		return fmt.Errorf("encrypt evidence: %w", err)
	}

	fullPath := filepath.Join(es.basePath, path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	return os.WriteFile(fullPath, encrypted, 0600)
}

func (es *EvidenceStorage) Load(id string) (*EvidenceCapture, error) {
	fullPath := filepath.Join(es.basePath, id)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var evidence EvidenceCapture
	if err := json.Unmarshal(data, &evidence); err != nil {
		return nil, fmt.Errorf("unmarshal evidence: %w", err)
	}

	return &evidence, nil
}

func (es *EvidenceStorage) LoadEncrypted(id string, key []byte) (*EvidenceCapture, error) {
	fullPath := filepath.Join(es.basePath, id)
	encrypted, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	data, err := crypto.DecryptAESGCM(key, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt evidence: %w", err)
	}

	var evidence EvidenceCapture
	if err := json.Unmarshal(data, &evidence); err != nil {
		return nil, fmt.Errorf("unmarshal evidence: %w", err)
	}

	return &evidence, nil
}
