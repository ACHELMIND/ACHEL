package environment_detection

import (
	"os"
	"sync"
	"time"
)

type Timestomp struct {
	mu       sync.RWMutex
	modified bool
}

func NewTimestomp() *Timestomp {
	return &Timestomp{}
}

func (t *Timestomp) Touch(filePath string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	if err := os.Chtimes(filePath, now, now); err != nil {
		return err
	}

	t.modified = true
	return nil
}

func (t *Timestomp) SetTime(filePath string, accessTime, modTime time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := os.Chtimes(filePath, accessTime, modTime); err != nil {
		return err
	}

	t.modified = true
	return nil
}

func (t *Timestomp) MatchTime(filePath, targetFile string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	targetInfo, err := os.Stat(targetFile)
	if err != nil {
		return err
	}

	if err := os.Chtimes(filePath, targetInfo.ModTime(), targetInfo.ModTime()); err != nil {
		return err
	}

	t.modified = true
	return nil
}

func (t *Timestomp) RandomizeTime(filePath string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	randomTime := time.Now().Add(-time.Duration(30*24) * time.Hour)
	if err := os.Chtimes(filePath, randomTime, randomTime); err != nil {
		return err
	}

	t.modified = true
	return nil
}

func (t *Timestomp) IsModified() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.modified
}

func (t *Timestomp) GetFileInfo(filePath string) (os.FileInfo, error) {
	return os.Stat(filePath)
}

func (t *Timestomp) RestoreTime(filePath string, originalTime time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := os.Chtimes(filePath, originalTime, originalTime); err != nil {
		return err
	}

	return nil
}
