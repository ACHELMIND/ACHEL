package cleanup

import (
	"time"
)

type CleanupConfig struct {
	BasePath    string
	DBPath      string
	ToolsDir    string
	LogsDir     string
	ConfigsDir  string
	BackupsDir  string
	TargetHost  string
}

type CleanupResult struct {
	Success       bool              `json:"success"`
	CleanedItems  []string          `json:"cleaned_items"`
	FailedItems   []string          `json:"failed_items"`
	Duration      time.Duration     `json:"duration"`
	Timestamp     time.Time         `json:"timestamp"`
}

type CleanupVerification struct {
	IsClean    bool              `json:"is_clean"`
	Remaining  []string          `json:"remaining"`
	Verified   []string          `json:"verified"`
	Timestamp  time.Time         `json:"timestamp"`
}

type Manifest struct {
	ID        string            `json:"id"`
	CreatedAt time.Time         `json:"created_at"`
	Items     []ManifestItem    `json:"items"`
	Hash      string            `json:"hash"`
}

type ManifestItem struct {
	Path      string    `json:"path"`
	Hash      string    `json:"hash"`
	Size      int64     `json:"size"`
	Deleted   bool      `json:"deleted"`
	DeletedAt time.Time `json:"deleted_at"`
}
