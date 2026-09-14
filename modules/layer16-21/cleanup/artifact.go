package cleanup

import (
	"fmt"
	"os"
	"path/filepath"
)

type ArtifactCleanup struct {
	config *CleanupConfig
}

func NewArtifactCleanup(config *CleanupConfig) *ArtifactCleanup {
	return &ArtifactCleanup{config: config}
}

func (ac *ArtifactCleanup) DeleteTools() error {
	if ac.config.ToolsDir == "" {
		return nil
	}

	entries, err := os.ReadDir(ac.config.ToolsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read tools dir: %w", err)
	}

	for _, entry := range entries {
		p := filepath.Join(ac.config.ToolsDir, entry.Name())
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}

	return nil
}

func (ac *ArtifactCleanup) DeleteLogs() error {
	if ac.config.LogsDir == "" {
		return nil
	}

	entries, err := os.ReadDir(ac.config.LogsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read logs dir: %w", err)
	}

	for _, entry := range entries {
		p := filepath.Join(ac.config.LogsDir, entry.Name())
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}

	return nil
}

func (ac *ArtifactCleanup) DeleteConfigs() error {
	if ac.config.ConfigsDir == "" {
		return nil
	}

	entries, err := os.ReadDir(ac.config.ConfigsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read configs dir: %w", err)
	}

	for _, entry := range entries {
		p := filepath.Join(ac.config.ConfigsDir, entry.Name())
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}

	return nil
}

func (ac *ArtifactCleanup) DeleteBackups() error {
	if ac.config.BackupsDir == "" {
		return nil
	}

	entries, err := os.ReadDir(ac.config.BackupsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read backups dir: %w", err)
	}

	for _, entry := range entries {
		p := filepath.Join(ac.config.BackupsDir, entry.Name())
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}

	return nil
}

func (ac *ArtifactCleanup) verifyToolsClean() (bool, error) {
	if ac.config.ToolsDir == "" {
		return true, nil
	}
	return ac.isDirEmpty(ac.config.ToolsDir)
}

func (ac *ArtifactCleanup) verifyLogsClean() (bool, error) {
	if ac.config.LogsDir == "" {
		return true, nil
	}
	return ac.isDirEmpty(ac.config.LogsDir)
}

func (ac *ArtifactCleanup) verifyConfigsClean() (bool, error) {
	if ac.config.ConfigsDir == "" {
		return true, nil
	}
	return ac.isDirEmpty(ac.config.ConfigsDir)
}

func (ac *ArtifactCleanup) verifyBackupsClean() (bool, error) {
	if ac.config.BackupsDir == "" {
		return true, nil
	}
	return ac.isDirEmpty(ac.config.BackupsDir)
}

func (ac *ArtifactCleanup) isDirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}
	return len(entries) == 0, nil
}
