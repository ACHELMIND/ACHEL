package iot

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(IoTConfig{
		TargetIP:    "192.168.1.50",
		TargetPort:  80,
		FirmwarePath: "/tmp/firmware.bin",
	})
}

func TestFirmwareExtract(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.FirmwareExtract("/tmp/router_firmware.bin")
	if err != nil {
		t.Fatalf("FirmwareExtract failed: %v", err)
	}
	if !result.Success {
		t.Error("FirmwareExtract reported failure")
	}
	if result.Method != "Firmware_Extract" {
		t.Errorf("expected method Firmware_Extract, got %s", result.Method)
	}
}

func TestFirmwareExtractCamera(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.FirmwareExtract("/tmp/camera_firmware.bin")
	if err != nil {
		t.Fatalf("FirmwareExtract failed: %v", err)
	}
	if !strings.Contains(result.Data, "IPCamera") {
		t.Error("should detect camera firmware")
	}
}

func TestCredentialDump(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CredentialDump("/tmp/firmware.bin")
	if err != nil {
		t.Fatalf("CredentialDump failed: %v", err)
	}
	if !result.Success {
		t.Error("CredentialDump reported failure")
	}
	if result.Risk != "critical" {
		t.Errorf("expected critical risk, got %s", result.Risk)
	}
}

func TestCredentialDumpFindsDefault(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CredentialDump("/tmp/firmware.bin")
	if err != nil {
		t.Fatalf("CredentialDump failed: %v", err)
	}
	if !strings.Contains(result.Data, "admin") {
		t.Error("should find default admin credentials")
	}
}

func TestHardcodedKey(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.HardcodedKey("/tmp/firmware.bin")
	if err != nil {
		t.Fatalf("HardcodedKey failed: %v", err)
	}
	if !result.Success {
		t.Error("HardcodedKey reported failure")
	}
	if !strings.Contains(result.Data, "RSA") {
		t.Error("should find RSA key")
	}
}

func TestBackdoorDetect(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.BackdoorDetect("/tmp/firmware.bin")
	if err != nil {
		t.Fatalf("BackdoorDetect failed: %v", err)
	}
	if !result.Success {
		t.Error("BackdoorDetect reported failure")
	}
	if result.Risk != "critical" {
		t.Errorf("expected critical risk, got %s", result.Risk)
	}
}

func TestBackdoorDetectFindsDebug(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.BackdoorDetect("/tmp/firmware.bin")
	if err != nil {
		t.Fatalf("BackdoorDetect failed: %v", err)
	}
	if !strings.Contains(result.Data, "debug") {
		t.Error("should find debug backdoor")
	}
}

func TestGetAnalysis(t *testing.T) {
	eng := newTestEngine()
	eng.CredentialDump("/tmp/firmware.bin")
	eng.HardcodedKey("/tmp/firmware.bin")
	eng.BackdoorDetect("/tmp/firmware.bin")

	analysis := eng.GetAnalysis()
	if len(analysis.Credentials) == 0 {
		t.Error("should have credentials")
	}
	if len(analysis.HardcodedKeys) == 0 {
		t.Error("should have hardcoded keys")
	}
	if len(analysis.Backdoors) == 0 {
		t.Error("should have backdoors")
	}
}

func TestAnalyzeStrings(t *testing.T) {
	eng := newTestEngine()
	data := "config: password=secret123 api_token=abc123"
	suspicious := eng.AnalyzeStrings(data)
	if len(suspicious) == 0 {
		t.Error("should find suspicious strings")
	}
}

func TestDefaultPort(t *testing.T) {
	eng := NewEngine(IoTConfig{TargetIP: "10.0.0.1"})
	if eng.config.TargetPort != 80 {
		t.Errorf("expected default port 80, got %d", eng.config.TargetPort)
	}
}
