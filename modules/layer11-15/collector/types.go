package collector

import (
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type CollectCategory string

const (
	CategoryScreen    CollectCategory = "screen"
	CategoryKeylog    CollectCategory = "keylog"
	CategoryClipboard CollectCategory = "clipboard"
	CategoryWebcam    CollectCategory = "webcam"
	CategoryWiFi      CollectCategory = "wifi"
	CategoryFileGrab  CollectCategory = "filegrab"
)

type CollectorConfig struct {
	Platform     types.Platform     `json:"platform"`
	Categories   []CollectCategory  `json:"categories"`
	Stealth      bool               `json:"stealth"`
	Timeout      time.Duration      `json:"timeout"`
	OutputPath   string             `json:"output_path"`
	MaxFileSize  int64              `json:"max_file_size"`
	MaxDepth     int                `json:"max_depth"`
	FilePatterns []string           `json:"file_patterns"`
	Metadata     map[string]string  `json:"metadata"`
}

func DefaultCollectorConfig() *CollectorConfig {
	return &CollectorConfig{
		Platform:     types.PlatformWindows,
		Categories:   []CollectCategory{CategoryScreen, CategoryKeylog, CategoryClipboard},
		Stealth:      false,
		Timeout:      60 * time.Second,
		MaxFileSize:  10 * 1024 * 1024,
		MaxDepth:     5,
		FilePatterns: []string{"*.txt", "*.doc", "*.pdf", "*.key"},
		Metadata:     make(map[string]string),
	}
}

type ScreenCapture struct {
	Data      []byte    `json:"data"`
	Width     int       `json:"width"`
	Height    int       `json:"height"`
	Format    string    `json:"format"`
	Timestamp time.Time `json:"timestamp"`
}

type ScreenRecord struct {
	Data      []byte        `json:"data"`
	Duration  time.Duration `json:"duration"`
	Format    string        `json:"format"`
	Timestamp time.Time     `json:"timestamp"`
}

type KeylogEntry struct {
	Process   string    `json:"process"`
	Key       string    `json:"key"`
	Timestamp time.Time `json:"timestamp"`
}

type ClipboardContent struct {
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

type WebcamCapture struct {
	Data      []byte    `json:"data"`
	Width     int       `json:"width"`
	Height    int       `json:"height"`
	Format    string    `json:"format"`
	Timestamp time.Time `json:"timestamp"`
}

type WiFiProfile struct {
	SSID      string `json:"ssid"`
	Auth      string `json:"auth"`
	EncType   string `json:"enc_type"`
	Password  string `json:"password"`
}

type FileInfo struct {
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	ModTime   time.Time `json:"mod_time"`
	IsDir     bool      `json:"is_dir"`
	Extension string    `json:"extension"`
}

type CollectResult struct {
	Success     bool                `json:"success"`
	Category    CollectCategory     `json:"category"`
	Screen      *ScreenCapture      `json:"screen,omitempty"`
	Record      *ScreenRecord       `json:"record,omitempty"`
	Keylog      []KeylogEntry       `json:"keylog,omitempty"`
	Clipboard   *ClipboardContent   `json:"clipboard,omitempty"`
	Webcam      *WebcamCapture      `json:"webcam,omitempty"`
	WiFi        []WiFiProfile       `json:"wifi,omitempty"`
	Files       []FileInfo          `json:"files,omitempty"`
	Error       string              `json:"error"`
	Timestamp   time.Time           `json:"timestamp"`
}
