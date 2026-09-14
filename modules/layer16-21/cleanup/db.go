package cleanup

import (
	"fmt"
	"os"
	"path/filepath"
)

type DatabaseCleanup struct {
	config *CleanupConfig
}

func NewDatabaseCleanup(config *CleanupConfig) *DatabaseCleanup {
	return &DatabaseCleanup{config: config}
}

func (dc *DatabaseCleanup) DeleteJavaObjects() error {
	if dc.config.DBPath == "" {
		return nil
	}

	javaPatterns := []string{"*.ser", "*.class", "*.jar"}
	return dc.deleteByPatterns(javaPatterns)
}

func (dc *DatabaseCleanup) DeleteStoredProcs() error {
	if dc.config.DBPath == "" {
		return nil
	}

	spDir := filepath.Join(dc.config.DBPath, "stored_procs")
	return os.RemoveAll(spDir)
}

func (dc *DatabaseCleanup) DeleteAdminAccounts() error {
	if dc.config.DBPath == "" {
		return nil
	}

	adminFile := filepath.Join(dc.config.DBPath, "admin_accounts.json")
	return os.Remove(adminFile)
}

func (dc *DatabaseCleanup) RevertChanges() error {
	if dc.config.DBPath == "" {
		return nil
	}

	changesDir := filepath.Join(dc.config.DBPath, "changes")
	entries, err := os.ReadDir(changesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read changes dir: %w", err)
	}

	for _, entry := range entries {
		p := filepath.Join(changesDir, entry.Name())
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}

	return nil
}

func (dc *DatabaseCleanup) deleteByPatterns(patterns []string) error {
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(dc.config.DBPath, pattern))
		if err != nil {
			return fmt.Errorf("glob %s: %w", pattern, err)
		}
		for _, m := range matches {
			if err := os.Remove(m); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove %s: %w", m, err)
			}
		}
	}
	return nil
}

func (dc *DatabaseCleanup) verifyDatabaseClean() (bool, error) {
	if dc.config.DBPath == "" {
		return true, nil
	}

	javaPatterns := []string{"*.ser", "*.class", "*.jar"}
	for _, pattern := range javaPatterns {
		matches, err := filepath.Glob(filepath.Join(dc.config.DBPath, pattern))
		if err != nil {
			return false, err
		}
		if len(matches) > 0 {
			return false, nil
		}
	}

	spDir := filepath.Join(dc.config.DBPath, "stored_procs")
	if _, err := os.Stat(spDir); err == nil {
		return false, nil
	}

	adminFile := filepath.Join(dc.config.DBPath, "admin_accounts.json")
	if _, err := os.Stat(adminFile); err == nil {
		return false, nil
	}

	return true, nil
}
