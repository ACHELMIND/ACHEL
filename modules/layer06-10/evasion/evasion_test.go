package evasion

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSyscallManagerCreation(t *testing.T) {
	sm := NewSyscallManager()
	if sm == nil {
		t.Fatal("NewSyscallManager returned nil")
	}

	methods := sm.ListMethods()
	if len(methods) != 7 {
		t.Errorf("Expected 7 methods, got %d", len(methods))
	}

	expected := []string{
		"HellsGate", "HalosGate", "TartarusGate",
		"FreshyCalls", "SysWhispers3", "IndirectSyscall", "RecycledGate",
	}
	for _, name := range expected {
		if _, ok := sm.GetMethod(name); !ok {
			t.Errorf("Method %s not found", name)
		}
	}
}

func TestSyscallMethodDescriptions(t *testing.T) {
	sm := NewSyscallManager()
	for _, name := range sm.ListMethods() {
		method, ok := sm.GetMethod(name)
		if !ok {
			t.Errorf("GetMethod(%s) returned false", name)
			continue
		}
		if method.Name() != name {
			t.Errorf("Method name mismatch: got %s, want %s", method.Name(), name)
		}
		if method.Description() == "" {
			t.Errorf("Method %s has empty description", name)
		}
		if method.Category() != CategorySyscall {
			t.Errorf("Method %s has wrong category: %s", name, method.Category())
		}
	}
}

func TestSyscallManagerFallbackChain(t *testing.T) {
	sm := NewSyscallManager()

	chain := []string{"HellsGate", "HalosGate", "FreshyCalls"}
	sm.SetFallbackChain(chain)

	stats := sm.GetStats()
	if len(stats) != 0 {
		t.Errorf("Expected empty stats, got %d entries", len(stats))
	}

	stub := &SyscallStub{
		SSN:      0x18,
		Module:   "ntdll",
		Function: "NtAllocateVirtualMemory",
	}

	_, err := sm.ExecuteWithFallback(stub, 0, 0, 0x1000, 0x1000, 0x3000)
	if err != nil {
		t.Logf("ExecuteWithFallback returned (expected in test): %v", err)
	}
}

func TestSyscallManagerGetRandomMethod(t *testing.T) {
	sm := NewSyscallManager()

	for i := 0; i < 10; i++ {
		method := sm.GetRandomMethod()
		if method == nil {
			t.Error("GetRandomMethod returned nil")
		}
	}
}

func TestCreateStub(t *testing.T) {
	stub := CreateStub("NtAllocateVirtualMemory", "ntdll", "NtAllocateVirtualMemory", 0x18)
	if stub == nil {
		t.Fatal("CreateStub returned nil")
	}
	if stub.SSN != 0x18 {
		t.Errorf("Expected SSN 0x18, got 0x%X", stub.SSN)
	}
	if stub.Module != "ntdll" {
		t.Errorf("Expected module ntdll, got %s", stub.Module)
	}
	if stub.Function != "NtAllocateVirtualMemory" {
		t.Errorf("Expected function NtAllocateVirtualMemory, got %s", stub.Function)
	}
}

func TestAntiAnalysisEngineCreation(t *testing.T) {
	engine := NewAntiAnalysisEngine()
	if engine == nil {
		t.Fatal("NewAntiAnalysisEngine returned nil")
	}
}

func TestAntiAnalysisRunAll(t *testing.T) {
	engine := NewAntiAnalysisEngine()
	results := engine.RunAll()
	if len(results) == 0 {
		t.Error("RunAll returned no results")
	}

	expectedCount := 15
	if len(results) != expectedCount {
		t.Errorf("Expected %d results, got %d", expectedCount, len(results))
	}

	for _, r := range results {
		if r.Method == "" {
			t.Error("Detection result has empty method")
		}
		if r.Timestamp.IsZero() {
			t.Errorf("Detection result %s has zero timestamp", r.Method)
		}
		if r.RiskScore < 0 || r.RiskScore > 1 {
			t.Errorf("Detection result %s has invalid risk score: %f", r.Method, r.RiskScore)
		}
	}
}

func TestAntiAnalysisDebuggerChecks(t *testing.T) {
	engine := NewAntiAnalysisEngine()
	results := engine.RunDebuggerChecks()
	if len(results) != 5 {
		t.Errorf("Expected 5 debugger checks, got %d", len(results))
	}

	for _, r := range results {
		if r.Type != DetectionDebugger {
			t.Errorf("Expected debugger detection type, got %s", r.Type)
		}
	}
}

func TestAntiAnalysisVMChecks(t *testing.T) {
	engine := NewAntiAnalysisEngine()
	results := engine.RunVMChecks()
	if len(results) != 5 {
		t.Errorf("Expected 5 VM checks, got %d", len(results))
	}

	for _, r := range results {
		if r.Type != DetectionVM {
			t.Errorf("Expected VM detection type, got %s", r.Type)
		}
	}
}

func TestAntiAnalysisSandboxChecks(t *testing.T) {
	engine := NewAntiAnalysisEngine()
	results := engine.RunSandboxChecks()
	if len(results) != 5 {
		t.Errorf("Expected 5 sandbox checks, got %d", len(results))
	}

	for _, r := range results {
		if r.Type != DetectionSandbox {
			t.Errorf("Expected sandbox detection type, got %s", r.Type)
		}
	}
}

func TestAntiAnalysisIsAnalyzed(t *testing.T) {
	engine := NewAntiAnalysisEngine()
	_ = engine.IsAnalyzed()
}

func TestAntiAnalysisReport(t *testing.T) {
	engine := NewAntiAnalysisEngine()
	report := engine.GenerateReport()
	if report == nil {
		t.Fatal("GenerateReport returned nil")
	}
	if report.Module != "AntiAnalysis" {
		t.Errorf("Expected module AntiAnalysis, got %s", report.Module)
	}
	if len(report.Results) == 0 {
		t.Error("Report has no results")
	}
	reportStr := report.String()
	if reportStr == "" {
		t.Error("Report String() returned empty")
	}
}

func TestTimingRDTSC(t *testing.T) {
	detector := &TimingRDTSC{}
	result := detector.Detect()
	if result.Method != "TimingRDTSC" {
		t.Errorf("Expected method TimingRDTSC, got %s", result.Method)
	}
	if result.Type != DetectionDebugger {
		t.Errorf("Expected debugger type, got %s", result.Type)
	}
}

func TestCoreCountCheck(t *testing.T) {
	detector := &CoreCountCheck{}
	result := detector.Detect()
	if result.Method != "CoreCountCheck" {
		t.Errorf("Expected method CoreCountCheck, got %s", result.Method)
	}
}

func TestUptimeCheck(t *testing.T) {
	detector := &UptimeCheck{}
	result := detector.Detect()
	if result.Method != "UptimeCheck" {
		t.Errorf("Expected method UptimeCheck, got %s", result.Method)
	}
}

func TestInjectionEngineCreation(t *testing.T) {
	engine := NewInjectionEngine()
	if engine == nil {
		t.Fatal("NewInjectionEngine returned nil")
	}

	methods := engine.ListMethods()
	if len(methods) != 7 {
		t.Errorf("Expected 7 injection methods, got %d", len(methods))
	}

	expected := []string{
		"CreateRemoteThread", "QueueUserAPC", "ProcessHollowing",
		"ThreadHijacking", "ModuleStomping", "ReflectiveDLL", "SectionMapping",
	}
	for _, name := range expected {
		if _, ok := engine.GetMethod(name); !ok {
			t.Errorf("Injection method %s not found", name)
		}
	}
}

func TestInjectionMethodDescriptions(t *testing.T) {
	engine := NewInjectionEngine()
	for _, name := range engine.ListMethods() {
		method, ok := engine.GetMethod(name)
		if !ok {
			t.Errorf("GetMethod(%s) returned false", name)
			continue
		}
		if method.Description() == "" {
			t.Errorf("Method %s has empty description", name)
		}
		if method.Category() != CategoryInjection {
			t.Errorf("Method %s has wrong category: %s", name, method.Category())
		}
	}
}

func TestInjectionEngineValidation(t *testing.T) {
	engine := NewInjectionEngine()

	method, _ := engine.GetMethod("CreateRemoteThread")

	err := method.Validate(nil)
	if err != ErrInvalidConfig {
		t.Errorf("Expected ErrInvalidConfig, got %v", err)
	}

	err = method.Validate(&InjectionConfig{TargetPID: -1})
	if err != ErrInvalidPID {
		t.Errorf("Expected ErrInvalidPID, got %v", err)
	}

	err = method.Validate(&InjectionConfig{TargetPID: 123, Payload: nil})
	if err != ErrPayloadEmpty {
		t.Errorf("Expected ErrPayloadEmpty, got %v", err)
	}

	err = method.Validate(&InjectionConfig{TargetPID: 123, Payload: []byte{0x90}})
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
}

func TestInjectionEngineExecute(t *testing.T) {
	engine := NewInjectionEngine()

	err := engine.Execute("NonExistentMethod", &InjectionConfig{})
	if err == nil {
		t.Error("Expected error for non-existent method")
	}

	config := &InjectionConfig{
		TargetPID: 123,
		Payload:   []byte{0x90, 0xCC},
	}

	err = engine.Execute("CreateRemoteThread", config)
	if err != nil {
		t.Errorf("Execute failed: %v", err)
	}

	stats := engine.GetStats()
	if stats["CreateRemoteThread"].Attempts != 1 {
		t.Errorf("Expected 1 attempt, got %d", stats["CreateRemoteThread"].Attempts)
	}
	if stats["CreateRemoteThread"].Successes != 1 {
		t.Errorf("Expected 1 success, got %d", stats["CreateRemoteThread"].Successes)
	}
}

func TestInjectionEngineSuccessRate(t *testing.T) {
	engine := NewInjectionEngine()

	config := &InjectionConfig{
		TargetPID: 123,
		Payload:   []byte{0x90},
	}

	_ = engine.Execute("CreateRemoteThread", config)
	rate := engine.GetSuccessRate("CreateRemoteThread")
	if rate != 1.0 {
		t.Errorf("Expected 1.0 success rate, got %f", rate)
	}

	rate = engine.GetSuccessRate("NonExistent")
	if rate != 0.0 {
		t.Errorf("Expected 0.0 success rate for non-existent, got %f", rate)
	}
}

func TestLogCleanupCreation(t *testing.T) {
	lc := NewLogCleanup(nil)
	if lc == nil {
		t.Fatal("NewLogCleanup returned nil")
	}

	config := lc.GetConfig()
	if !config.ClearEventLogs {
		t.Error("Expected ClearEventLogs to be true")
	}
	if !config.ClearPrefetch {
		t.Error("Expected ClearPrefetch to be true")
	}
	if !config.ClearShellHistory {
		t.Error("Expected ClearShellHistory to be true")
	}
	if !config.ClearForensics {
		t.Error("Expected ClearForensics to be true")
	}
}

func TestLogCleanupDryRun(t *testing.T) {
	config := &CleanupConfig{
		ClearEventLogs:    true,
		ClearPrefetch:     true,
		ClearShellHistory: true,
		ClearForensics:    true,
		DryRun:            true,
	}

	lc := NewLogCleanup(config)

	err := lc.ClearEventLogs()
	if err != nil {
		t.Errorf("ClearEventLogs dry run failed: %v", err)
	}

	err = lc.ClearPrefetch()
	if err != nil {
		t.Errorf("ClearPrefetch dry run failed: %v", err)
	}

	err = lc.ClearShellHistory()
	if err != nil {
		t.Errorf("ClearShellHistory dry run failed: %v", err)
	}

	err = lc.ClearForensicArtifacts()
	if err != nil {
		t.Errorf("ClearForensicArtifacts dry run failed: %v", err)
	}

	err = lc.FullCleanup()
	if err != nil {
		t.Errorf("FullCleanup dry run failed: %v", err)
	}

	log := lc.GetLog()
	if len(log) == 0 {
		t.Error("Expected log entries")
	}
}

func TestLogCleanupLogFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	err := os.WriteFile(logFile, []byte("test log content\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test log: %v", err)
	}

	lc := NewLogCleanup(&CleanupConfig{
		MaxAge: 1 * time.Hour,
	})

	err = lc.clearLogFile(logFile)
	if err != nil {
		t.Errorf("clearLogFile failed: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("Expected empty log file, got %d bytes", len(data))
	}
}

func TestLogCleanupClearShellHistory(t *testing.T) {
	tmpDir := t.TempDir()
	historyFile := filepath.Join(tmpDir, ".bash_history")

	err := os.WriteFile(historyFile, []byte("ls -la\nwhoami\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to create history file: %v", err)
	}

	t.Setenv("HOME", tmpDir)

	lc := NewLogCleanup(&CleanupConfig{
		ClearShellHistory: true,
		DryRun:            true,
	})

	err = lc.ClearShellHistory()
	if err != nil {
		t.Errorf("ClearShellHistory failed: %v", err)
	}
}

func TestLogCleanupGetLog(t *testing.T) {
	lc := NewLogCleanup(&CleanupConfig{DryRun: true})
	_ = lc.ClearEventLogs()

	log := lc.GetLog()
	if len(log) == 0 {
		t.Error("Expected log entries after operation")
	}

	lc.ResetLog()
	log = lc.GetLog()
	if len(log) != 0 {
		t.Error("Expected empty log after reset")
	}
}

func TestNetworkEvasionCreation(t *testing.T) {
	ne := NewNetworkEvasion(nil)
	if ne == nil {
		t.Fatal("NewNetworkEvasion returned nil")
	}
}

func TestNetworkEvasionRotateIP(t *testing.T) {
	config := &NetworkEvasionConfig{
		IPPool: []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"},
	}

	ne := NewNetworkEvasion(config)

	ip1 := ne.RotateIP()
	ip2 := ne.RotateIP()
	ip3 := ne.RotateIP()
	ip4 := ne.RotateIP()

	if ip1 != "1.1.1.1" {
		t.Errorf("Expected 1.1.1.1, got %s", ip1)
	}
	if ip2 != "2.2.2.2" {
		t.Errorf("Expected 2.2.2.2, got %s", ip2)
	}
	if ip3 != "3.3.3.3" {
		t.Errorf("Expected 3.3.3.3, got %s", ip3)
	}
	if ip4 != "1.1.1.1" {
		t.Errorf("Expected wrap to 1.1.1.1, got %s", ip4)
	}
}

func TestNetworkEvasionRotateUserAgent(t *testing.T) {
	config := &NetworkEvasionConfig{
		UserAgents: []string{"UA1", "UA2", "UA3"},
	}

	ne := NewNetworkEvasion(config)

	ua1 := ne.RotateUserAgent()
	ua2 := ne.RotateUserAgent()
	ua3 := ne.RotateUserAgent()
	ua4 := ne.RotateUserAgent()

	if ua1 != "UA1" {
		t.Errorf("Expected UA1, got %s", ua1)
	}
	if ua2 != "UA2" {
		t.Errorf("Expected UA2, got %s", ua2)
	}
	if ua3 != "UA3" {
		t.Errorf("Expected UA3, got %s", ua3)
	}
	if ua4 != "UA1" {
		t.Errorf("Expected wrap to UA1, got %s", ua4)
	}
}

func TestNetworkEvasionRotateTLSFingerprint(t *testing.T) {
	config := &NetworkEvasionConfig{
		TLSFingerprints: []string{"chrome", "firefox", "safari"},
	}

	ne := NewNetworkEvasion(config)

	fp1 := ne.RotateTLSFingerprint()
	fp2 := ne.RotateTLSFingerprint()
	fp3 := ne.RotateTLSFingerprint()
	fp4 := ne.RotateTLSFingerprint()

	if fp1 != "chrome" {
		t.Errorf("Expected chrome, got %s", fp1)
	}
	if fp2 != "firefox" {
		t.Errorf("Expected firefox, got %s", fp2)
	}
	if fp3 != "safari" {
		t.Errorf("Expected safari, got %s", fp3)
	}
	if fp4 != "chrome" {
		t.Errorf("Expected wrap to chrome, got %s", fp4)
	}
}

func TestNetworkEvasionEncodeDNSHex(t *testing.T) {
	config := &NetworkEvasionConfig{DNSEncodingType: "hex"}
	ne := NewNetworkEvasion(config)

	encoded := ne.EncodeDNS([]byte("hello"))
	if encoded == "" {
		t.Error("Expected non-empty encoded string")
	}

	parts := strings.Split(encoded, ".")
	for _, part := range parts {
		for _, c := range part {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("Invalid hex character in encoded DNS: %c", c)
				break
			}
		}
	}
}

func TestNetworkEvasionEncodeDNSBase32(t *testing.T) {
	config := &NetworkEvasionConfig{DNSEncodingType: "base32"}
	ne := NewNetworkEvasion(config)

	encoded := ne.EncodeDNS([]byte("hello world"))
	if encoded == "" {
		t.Error("Expected non-empty encoded string")
	}
}

func TestNetworkEvasionEncodeDNSBase64(t *testing.T) {
	config := &NetworkEvasionConfig{DNSEncodingType: "base64dns"}
	ne := NewNetworkEvasion(config)

	encoded := ne.EncodeDNS([]byte("hello world"))
	if encoded == "" {
		t.Error("Expected non-empty encoded string")
	}
}

func TestNetworkEvasionEncodeDNSChunked(t *testing.T) {
	config := &NetworkEvasionConfig{DNSEncodingType: "chunked"}
	ne := NewNetworkEvasion(config)

	encoded := ne.EncodeDNS([]byte("test data here"))
	if encoded == "" {
		t.Error("Expected non-empty encoded string")
	}

	parts := strings.Split(encoded, ".")
	if len(parts) < 2 {
		t.Errorf("Expected multiple chunks, got %d", len(parts))
	}
}

func TestNetworkEvasionEncodeDNSDefault(t *testing.T) {
	config := &NetworkEvasionConfig{DNSEncodingType: "unknown"}
	ne := NewNetworkEvasion(config)

	encoded := ne.EncodeDNS([]byte("test"))
	if encoded == "" {
		t.Error("Expected non-empty encoded string")
	}
}

func TestNetworkEvasionEncodeDNSEmpty(t *testing.T) {
	config := &NetworkEvasionConfig{DNSEncodingType: "hex"}
	ne := NewNetworkEvasion(config)

	encoded := ne.EncodeDNS([]byte{})
	if encoded != "" {
		t.Errorf("Expected empty string, got %s", encoded)
	}
}

func TestNetworkEvasionMorphTrafficPattern(t *testing.T) {
	config := &NetworkEvasionConfig{TrafficMorphing: true}
	ne := NewNetworkEvasion(config)

	pattern1 := ne.MorphTrafficPattern()
	pattern2 := ne.MorphTrafficPattern()

	if len(pattern1) == 0 {
		t.Error("Expected non-empty pattern")
	}
	if len(pattern2) == 0 {
		t.Error("Expected non-empty pattern")
	}

	state := ne.GetTrafficState()
	if state.MorphCount != 2 {
		t.Errorf("Expected morph count 2, got %d", state.MorphCount)
	}
}

func TestNetworkEvasionApplyJitter(t *testing.T) {
	config := &NetworkEvasionConfig{JitterPercent: 0.25}
	ne := NewNetworkEvasion(config)

	base := 10 * time.Second
	jittered := ne.ApplyJitter(base)

	if jittered < 100*time.Millisecond {
		t.Errorf("Jittered interval too small: %v", jittered)
	}
}

func TestNetworkEvasionObfuscateDeobfuscate(t *testing.T) {
	config := NewDefaultNetworkConfig()
	ne := NewNetworkEvasion(config)

	original := []byte("secret payload data 12345")
	obfuscated := ne.ObfuscatePayload(original)

	if bytes.Equal(obfuscated, original) {
		t.Error("Obfuscated payload should differ from original")
	}

	deobfuscated := ne.DeobfuscatePayload(obfuscated)
	if !bytes.Equal(deobfuscated, original) {
		t.Errorf("Deobfuscated payload differs from original")
	}
}

func TestNetworkEvasionObfuscateEmpty(t *testing.T) {
	config := NewDefaultNetworkConfig()
	ne := NewNetworkEvasion(config)

	obfuscated := ne.ObfuscatePayload([]byte{})
	if len(obfuscated) != 0 {
		t.Errorf("Expected empty obfuscated payload, got %d bytes", len(obfuscated))
	}

	deobfuscated := ne.DeobfuscatePayload([]byte{})
	if len(deobfuscated) != 0 {
		t.Errorf("Expected empty deobfuscated payload, got %d bytes", len(deobfuscated))
	}
}

func TestNetworkEvasionObfuscateSmallPayload(t *testing.T) {
	config := NewDefaultNetworkConfig()
	ne := NewNetworkEvasion(config)

	deobfuscated := ne.DeobfuscatePayload([]byte{0x01})
	if !bytes.Equal(deobfuscated, []byte{0x01}) {
		t.Error("Single byte deobfuscate should return same byte")
	}
}

func TestNetworkEvasionGenerateRandomDomain(t *testing.T) {
	config := NewDefaultNetworkConfig()
	ne := NewNetworkEvasion(config)

	domain := ne.GenerateRandomDomain(16)
	if len(domain) != 16 {
		t.Errorf("Expected domain length 16, got %d", len(domain))
	}

	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			t.Errorf("Invalid character in random domain: %c", c)
		}
	}
}

func TestNetworkEvasionString(t *testing.T) {
	ne := NewNetworkEvasion(nil)
	str := ne.String()
	if str == "" {
		t.Error("String() returned empty")
	}
	if !strings.Contains(str, "NetworkEvasion") {
		t.Errorf("String() missing prefix: %s", str)
	}
}

func TestNetworkEvasionGetTrafficState(t *testing.T) {
	config := &NetworkEvasionConfig{JitterPercent: 0.1}
	ne := NewNetworkEvasion(config)

	state := ne.GetTrafficState()
	if state == nil {
		t.Fatal("GetTrafficState returned nil")
	}
	if !state.JitterActive {
		t.Error("Expected JitterActive to be true")
	}
}

func TestNetworkEvasionGetConfig(t *testing.T) {
	config := NewDefaultNetworkConfig()
	ne := NewNetworkEvasion(config)

	gotConfig := ne.GetConfig()
	if gotConfig != config {
		t.Error("GetConfig returned different config")
	}
}

func TestEvasionReport(t *testing.T) {
	report := &EvasionReport{
		Module:    "TestModule",
		Timestamp: time.Now(),
	}

	result1 := DetectionResult{
		Type:      DetectionDebugger,
		Detected:  true,
		Method:    "TestDetector",
		Details:   "Test details",
		RiskScore: 0.8,
		Timestamp: time.Now(),
	}

	result2 := DetectionResult{
		Type:      DetectionVM,
		Detected:  false,
		Method:    "CleanDetector",
		Details:   "Nothing found",
		RiskScore: 0.0,
		Timestamp: time.Now(),
	}

	report.AddResult(result1)
	report.AddResult(result2)

	if report.RiskScore != 0.8 {
		t.Errorf("Expected risk score 0.8, got %f", report.RiskScore)
	}

	if len(report.Results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(report.Results))
	}

	str := report.String()
	if str == "" {
		t.Error("String() returned empty")
	}
}

func TestEvasionReportMaxRiskScore(t *testing.T) {
	report := &EvasionReport{
		Module:    "Test",
		Timestamp: time.Now(),
	}

	report.AddResult(DetectionResult{
		Detected:  true,
		RiskScore: 0.3,
	})
	report.AddResult(DetectionResult{
		Detected:  true,
		RiskScore: 0.9,
	})

	if report.RiskScore != 0.9 {
		t.Errorf("Expected max risk score 0.9, got %f", report.RiskScore)
	}
}

func TestNewDefaultCleanupConfig(t *testing.T) {
	config := NewDefaultCleanupConfig()
	if !config.ClearEventLogs {
		t.Error("ClearEventLogs should be true")
	}
	if !config.ClearPrefetch {
		t.Error("ClearPrefetch should be true")
	}
	if !config.ClearShellHistory {
		t.Error("ClearShellHistory should be true")
	}
	if !config.ClearForensics {
		t.Error("ClearForensics should be true")
	}
	if config.MaxAge != 24*time.Hour {
		t.Errorf("Expected max age 24h, got %v", config.MaxAge)
	}
}

func TestNewDefaultNetworkConfig(t *testing.T) {
	config := NewDefaultNetworkConfig()
	if len(config.UserAgents) == 0 {
		t.Error("Expected non-empty UserAgents")
	}
	if len(config.TLSFingerprints) == 0 {
		t.Error("Expected non-empty TLSFingerprints")
	}
	if config.DNSEncodingType != "hex" {
		t.Errorf("Expected hex DNS encoding, got %s", config.DNSEncodingType)
	}
	if !config.TrafficMorphing {
		t.Error("Expected TrafficMorphing to be true")
	}
	if config.JitterPercent != 0.25 {
		t.Errorf("Expected jitter 0.25, got %f", config.JitterPercent)
	}
}

func TestIndividualAntiDetectors(t *testing.T) {
	detectors := []AntiDetector{
		&IsDebuggerPresent{},
		&CheckRemoteDebugger{},
		&NtGlobalFlag{},
		&HardwareBPCheck{},
		&TimingRDTSC{},
		&CPUIDHypervisor{},
		&MACAddressPrefix{},
		&RegistryKeys{},
		&DeviceDrivers{},
		&ProcessCheck{},
		&UptimeCheck{},
		&MouseNoMovement{},
		&DiskSizeCheck{},
		&CoreCountCheck{},
		&RAMSizeCheck{},
	}

	for _, det := range detectors {
		result := det.Detect()
		if result.Method == "" {
			t.Errorf("Detector %s returned empty method", det.Name())
		}
		if result.Timestamp.IsZero() {
			t.Errorf("Detector %s returned zero timestamp", det.Name())
		}
		if result.RiskScore < 0 || result.RiskScore > 1 {
			t.Errorf("Detector %s has invalid risk score: %f", det.Name(), result.RiskScore)
		}
		t.Logf("Detector %s: detected=%v, risk=%.2f, details=%s",
			det.Name(), result.Detected, result.RiskScore, result.Details)
	}
}

func TestCPUIDHypervisorDetection(t *testing.T) {
	detector := &CPUIDHypervisor{}
	result := detector.Detect()
	t.Logf("CPUID hypervisor detection: %v (risk: %.2f)", result.Detected, result.RiskScore)
}

func TestMACAddressPrefixDetection(t *testing.T) {
	detector := &MACAddressPrefix{}
	result := detector.Detect()
	t.Logf("MAC prefix detection: %v (risk: %.2f)", result.Detected, result.RiskScore)
}

func TestRegistryKeysDetection(t *testing.T) {
	detector := &RegistryKeys{}
	result := detector.Detect()
	t.Logf("Registry keys detection: %v (risk: %.2f)", result.Detected, result.RiskScore)
}

func TestDeviceDriversDetection(t *testing.T) {
	detector := &DeviceDrivers{}
	result := detector.Detect()
	t.Logf("Device drivers detection: %v (risk: %.2f)", result.Detected, result.RiskScore)
}

func TestProcessCheckDetection(t *testing.T) {
	detector := &ProcessCheck{}
	result := detector.Detect()
	t.Logf("Process check detection: %v (risk: %.2f)", result.Detected, result.RiskScore)
}

func TestRAMSizeCheckDetection(t *testing.T) {
	detector := &RAMSizeCheck{}
	result := detector.Detect()
	t.Logf("RAM size check: %v (risk: %.2f)", result.Detected, result.RiskScore)
}

func TestDiskSizeCheckDetection(t *testing.T) {
	detector := &DiskSizeCheck{}
	result := detector.Detect()
	t.Logf("Disk size check: %v (risk: %.2f)", result.Detected, result.RiskScore)
}

func TestMouseNoMovementDetection(t *testing.T) {
	detector := &MouseNoMovement{}
	result := detector.Detect()
	t.Logf("Mouse no movement: %v (risk: %.2f)", result.Detected, result.RiskScore)
}

func TestIsDebuggerPresentDetection(t *testing.T) {
	detector := &IsDebuggerPresent{}
	result := detector.Detect()
	t.Logf("IsDebuggerPresent: %v (risk: %.2f)", result.Detected, result.RiskScore)
}

func TestCheckRemoteDebuggerDetection(t *testing.T) {
	detector := &CheckRemoteDebugger{}
	result := detector.Detect()
	t.Logf("CheckRemoteDebugger: %v (risk: %.2f)", result.Detected, result.RiskScore)
}

func TestNtGlobalFlagDetection(t *testing.T) {
	detector := &NtGlobalFlag{}
	result := detector.Detect()
	t.Logf("NtGlobalFlag: %v (risk: %.2f)", result.Detected, result.RiskScore)
}

func TestHardwareBPCheckDetection(t *testing.T) {
	detector := &HardwareBPCheck{}
	result := detector.Detect()
	t.Logf("HardwareBPCheck: %v (risk: %.2f)", result.Detected, result.RiskScore)
}

func TestNetworkEvasionIPPoolWraparound(t *testing.T) {
	config := &NetworkEvasionConfig{
		IPPool: []string{"1.1.1.1"},
	}
	ne := NewNetworkEvasion(config)

	for i := 0; i < 10; i++ {
		ip := ne.RotateIP()
		if ip != "1.1.1.1" {
			t.Errorf("Expected 1.1.1.1 on iteration %d, got %s", i, ip)
		}
	}
}

func TestNetworkEvasionEmptyIPPool(t *testing.T) {
	config := &NetworkEvasionConfig{
		IPPool: []string{},
	}
	ne := NewNetworkEvasion(config)

	ip := ne.RotateIP()
	if ip == "" {
		t.Error("Expected non-empty IP (defaults added)")
	}
}

func TestNetworkEvasionEmptyUserAgents(t *testing.T) {
	config := &NetworkEvasionConfig{
		UserAgents: []string{},
	}
	ne := NewNetworkEvasion(config)

	ua := ne.RotateUserAgent()
	if ua != "Mozilla/5.0" {
		t.Errorf("Expected default UA, got %s", ua)
	}
}

func TestNetworkEvasionEmptyTLSFingerprints(t *testing.T) {
	config := &NetworkEvasionConfig{
		TLSFingerprints: []string{},
	}
	ne := NewNetworkEvasion(config)

	fp := ne.RotateTLSFingerprint()
	if fp != "unknown" {
		t.Errorf("Expected 'unknown', got %s", fp)
	}
}

func TestNetworkEvasionZeroJitter(t *testing.T) {
	config := &NetworkEvasionConfig{JitterPercent: 0}
	ne := NewNetworkEvasion(config)

	base := 5 * time.Second
	jittered := ne.ApplyJitter(base)
	if jittered != base {
		t.Errorf("Expected same interval with zero jitter, got %v", jittered)
	}
}

func TestNetworkEvasionTrafficMorphingDisabled(t *testing.T) {
	config := &NetworkEvasionConfig{TrafficMorphing: false}
	ne := NewNetworkEvasion(config)

	pattern := ne.MorphTrafficPattern()
	if len(pattern) != 0 {
		t.Error("Expected empty pattern when traffic morphing disabled")
	}
}

func TestSyscallManagerExecuteNonExistent(t *testing.T) {
	sm := NewSyscallManager()

	stub := &SyscallStub{SSN: 0x18}
	_, err := sm.ExecuteWithMethod("NonExistent", stub)
	if err == nil {
		t.Error("Expected error for non-existent method")
	}
}

func TestSyscallManagerRegisterDuplicate(t *testing.T) {
	sm := NewSyscallManager()

	method := NewHellsGate()
	sm.Register(method)
	sm.Register(method)

	methods := sm.ListMethods()
	count := 0
	for _, m := range methods {
		if m == "HellsGate" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Expected 1 HellsGate method, got %d", count)
	}
}

func TestHellsGateName(t *testing.T) {
	method := NewHellsGate()
	if method.Name() != "HellsGate" {
		t.Errorf("Expected HellsGate, got %s", method.Name())
	}
}

func TestHalosGateName(t *testing.T) {
	method := NewHalosGate()
	if method.Name() != "HalosGate" {
		t.Errorf("Expected HalosGate, got %s", method.Name())
	}
}

func TestTartarusGateName(t *testing.T) {
	method := NewTartarusGate()
	if method.Name() != "TartarusGate" {
		t.Errorf("Expected TartarusGate, got %s", method.Name())
	}
}

func TestFreshyCallsName(t *testing.T) {
	method := NewFreshyCalls()
	if method.Name() != "FreshyCalls" {
		t.Errorf("Expected FreshyCalls, got %s", method.Name())
	}
}

func TestSysWhispers3Name(t *testing.T) {
	method := NewSysWhispers3()
	if method.Name() != "SysWhispers3" {
		t.Errorf("Expected SysWhispers3, got %s", method.Name())
	}
}

func TestIndirectSyscallName(t *testing.T) {
	method := NewIndirectSyscall()
	if method.Name() != "IndirectSyscall" {
		t.Errorf("Expected IndirectSyscall, got %s", method.Name())
	}
}

func TestRecycledGateName(t *testing.T) {
	method := NewRecycledGate()
	if method.Name() != "RecycledGate" {
		t.Errorf("Expected RecycledGate, got %s", method.Name())
	}
}

func TestSyscallMethodsExecuteNilStub(t *testing.T) {
	methods := []SyscallMethod{
		NewHellsGate(),
		NewHalosGate(),
		NewTartarusGate(),
		NewFreshyCalls(),
		NewSysWhispers3(),
		NewIndirectSyscall(),
		NewRecycledGate(),
	}

	for _, method := range methods {
		_, err := method.Execute(nil)
		if err != ErrInvalidStub {
			t.Errorf("Method %s: expected ErrInvalidStub, got %v", method.Name(), err)
		}
	}
}

func TestInjectionMethodsValidateNilConfig(t *testing.T) {
	methods := []InjectionMethod{
		NewCreateRemoteThread(),
		NewQueueUserAPC(),
		NewProcessHollowing(),
		NewThreadHijacking(),
		NewModuleStomping(),
		NewReflectiveDLL(),
		NewSectionMapping(),
	}

	for _, method := range methods {
		err := method.Validate(nil)
		if err != ErrInvalidConfig {
			t.Errorf("Method %s: expected ErrInvalidConfig, got %v", method.Name(), err)
		}
	}
}

func TestInjectionMethodsValidateEmptyPayload(t *testing.T) {
	methods := []InjectionMethod{
		NewCreateRemoteThread(),
		NewQueueUserAPC(),
		NewProcessHollowing(),
		NewThreadHijacking(),
		NewModuleStomping(),
		NewReflectiveDLL(),
		NewSectionMapping(),
	}

	for _, method := range methods {
		err := method.Validate(&InjectionConfig{TargetPID: 123})
		if err != ErrPayloadEmpty {
			t.Errorf("Method %s: expected ErrPayloadEmpty, got %v", method.Name(), err)
		}
	}
}

func TestRecycledGateCacheStub(t *testing.T) {
	rg := NewRecycledGate()
	stub := &SyscallStub{SSN: 0x18, Function: "NtTest"}
	rg.CacheStub("test", stub)

	if _, ok := rg.stubCache["test"]; !ok {
		t.Error("Stub not cached")
	}
}

func TestFreshyCallsExtractSSN(t *testing.T) {
	fc := NewFreshyCalls()
	ssn := fc.extractFreshSSN("ntdll", "NtAllocateVirtualMemory")
	if ssn != 0x18 {
		t.Errorf("Expected SSN 0x18, got 0x%X", ssn)
	}

	ssn = fc.extractFreshSSN("ntdll", "NtWriteVirtualMemory")
	if ssn != 0x3A {
		t.Errorf("Expected SSN 0x3A, got 0x%X", ssn)
	}

	ssn = fc.extractFreshSSN("ntdll", "NonExistentFunc")
	if ssn != 0 {
		t.Errorf("Expected SSN 0 for unknown function, got 0x%X", ssn)
	}
}

func TestNetworkEvasionEncodeDNSLongData(t *testing.T) {
	config := &NetworkEvasionConfig{DNSEncodingType: "hex"}
	ne := NewNetworkEvasion(config)

	data := make([]byte, 256)
	rand.Read(data)

	encoded := ne.EncodeDNS(data)
	if encoded == "" {
		t.Error("Expected non-empty encoded string")
	}

	parts := strings.Split(encoded, ".")
	for _, part := range parts {
		if len(part) > 16 {
			t.Errorf("DNS label too long: %d chars", len(part))
		}
	}
}

func TestNetworkEvasionApplyJitterMinBound(t *testing.T) {
	config := &NetworkEvasionConfig{JitterPercent: 0.99}
	ne := NewNetworkEvasion(config)

	base := 50 * time.Millisecond
	for i := 0; i < 100; i++ {
		jittered := ne.ApplyJitter(base)
		if jittered < 100*time.Millisecond {
			t.Errorf("Jittered interval below minimum: %v", jittered)
			break
		}
	}
}

func TestLogCleanupClearForensicArtifacts(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_artifact.txt")

	err := os.WriteFile(testFile, []byte("test"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	config := &CleanupConfig{
		ClearForensics: true,
		MaxAge:         1 * time.Hour,
		DryRun:         true,
	}

	lc := NewLogCleanup(config)
	err = lc.ClearForensicArtifacts()
	if err != nil {
		t.Errorf("ClearForensicArtifacts failed: %v", err)
	}
}

func TestHellsGateExecuteNilStub(t *testing.T) {
	method := NewHellsGate()
	_, err := method.Execute(nil)
	if err != ErrInvalidStub {
		t.Errorf("Expected ErrInvalidStub, got %v", err)
	}
}

func TestHalosGateExecuteNilStub(t *testing.T) {
	method := NewHalosGate()
	_, err := method.Execute(nil)
	if err != ErrInvalidStub {
		t.Errorf("Expected ErrInvalidStub, got %v", err)
	}
}

func TestTartarusGateExecuteNilStub(t *testing.T) {
	method := NewTartarusGate()
	_, err := method.Execute(nil)
	if err != ErrInvalidStub {
		t.Errorf("Expected ErrInvalidStub, got %v", err)
	}
}

func TestFreshyCallsExecuteNilStub(t *testing.T) {
	method := NewFreshyCalls()
	_, err := method.Execute(nil)
	if err != ErrInvalidStub {
		t.Errorf("Expected ErrInvalidStub, got %v", err)
	}
}

func TestSysWhispers3ExecuteNilStub(t *testing.T) {
	method := NewSysWhispers3()
	_, err := method.Execute(nil)
	if err != ErrInvalidStub {
		t.Errorf("Expected ErrInvalidStub, got %v", err)
	}
}

func TestIndirectSyscallExecuteNilStub(t *testing.T) {
	method := NewIndirectSyscall()
	_, err := method.Execute(nil)
	if err != ErrInvalidStub {
		t.Errorf("Expected ErrInvalidStub, got %v", err)
	}
}

func TestRecycledGateExecuteNilStub(t *testing.T) {
	method := NewRecycledGate()
	_, err := method.Execute(nil)
	if err != ErrInvalidStub {
		t.Errorf("Expected ErrInvalidStub, got %v", err)
	}
}

func TestAllInjectionMethodsCategory(t *testing.T) {
	methods := []InjectionMethod{
		NewCreateRemoteThread(),
		NewQueueUserAPC(),
		NewProcessHollowing(),
		NewThreadHijacking(),
		NewModuleStomping(),
		NewReflectiveDLL(),
		NewSectionMapping(),
	}

	for _, method := range methods {
		if method.Category() != CategoryInjection {
			t.Errorf("Method %s has wrong category: %s", method.Name(), method.Category())
		}
	}
}

func TestTartarusGateBuildPrologue(t *testing.T) {
	tg := NewTartarusGate()
	prologue := tg.buildSyscallPrologue(0x18)
	if len(prologue) != 16 {
		t.Errorf("Expected prologue length 16, got %d", len(prologue))
	}
	if prologue[0] != 0x4C {
		t.Errorf("Expected 0x4C at offset 0, got 0x%X", prologue[0])
	}
}

func TestSysWhispers3GenerateShellcode(t *testing.T) {
	sw := NewSysWhispers3()
	stub := &SyscallStub{SSN: 0x18}
	shellcode := sw.generateIndirectSyscallShellcode(stub)
	if len(shellcode) == 0 {
		t.Error("Expected non-empty shellcode")
	}
	if shellcode[0] != 0x4C {
		t.Errorf("Expected 0x4C at start, got 0x%X", shellcode[0])
	}
}

func TestGenerateHash(t *testing.T) {
	hash1 := generateHash("test")
	hash2 := generateHash("test")
	if hash1 != hash2 {
		t.Error("Same input should produce same hash")
	}
	if len(hash1) != 64 {
		t.Errorf("Expected hash length 64, got %d", len(hash1))
	}
}

func TestAntiAnalysisConfig(t *testing.T) {
	engine := NewAntiAnalysisEngine()
	engine.config.EnableDebuggerChecks = false
	engine.config.EnableVMChecks = false
	engine.config.EnableSandboxChecks = false

	results := engine.RunAll()
	if len(results) != 0 {
		t.Errorf("Expected no results with all checks disabled, got %d", len(results))
	}
}

func TestNetworkEvasionEncodeDNSMultipleCalls(t *testing.T) {
	config := &NetworkEvasionConfig{DNSEncodingType: "hex"}
	ne := NewNetworkEvasion(config)

	for i := 0; i < 10; i++ {
		data := make([]byte, 32)
		rand.Read(data)
		encoded := ne.EncodeDNS(data)
		if encoded == "" {
			t.Errorf("Empty encoded result on call %d", i)
		}
	}
}

func TestSyscallManagerStatsConcurrency(t *testing.T) {
	sm := NewSyscallManager()

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_ = sm.GetStats()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestNetworkEvasionObfuscateDifferentEachTime(t *testing.T) {
	config := NewDefaultNetworkConfig()
	ne := NewNetworkEvasion(config)

	original := []byte("test payload")

	obf1 := ne.ObfuscatePayload(original)
	obf2 := ne.ObfuscatePayload(original)

	if bytes.Equal(obf1, obf2) {
		t.Error("Obfuscation should produce different results each time")
	}
}

func TestLogCleanupFullCleanupDryRun(t *testing.T) {
	config := &CleanupConfig{
		ClearEventLogs:    true,
		ClearPrefetch:     true,
		ClearShellHistory: true,
		ClearForensics:    true,
		DryRun:            true,
	}

	lc := NewLogCleanup(config)
	err := lc.FullCleanup()
	if err != nil {
		t.Errorf("FullCleanup dry run failed: %v", err)
	}

	log := lc.GetLog()
	if len(log) < 2 {
		t.Errorf("Expected at least 2 log entries, got %d", len(log))
	}
}

func TestInjectionEngineWithFallbackNoMethods(t *testing.T) {
	engine := &InjectionEngine{
		methods: make(map[string]InjectionMethod),
		stats:   make(map[string]*InjectionStats),
	}

	config := &InjectionConfig{
		TargetPID: 123,
		Payload:   []byte{0x90},
	}

	err := engine.ExecuteWithFallback(config)
	if err != ErrInjectionFailed {
		t.Errorf("Expected ErrInjectionFailed, got %v", err)
	}
}

func TestNetworkEvasionEncodeDNSNilData(t *testing.T) {
	config := &NetworkEvasionConfig{DNSEncodingType: "hex"}
	ne := NewNetworkEvasion(config)

	encoded := ne.EncodeDNS(nil)
	if encoded != "" {
		t.Errorf("Expected empty string for nil data, got %s", encoded)
	}
}

func TestLogCleanupRemoveDirectoryContents(t *testing.T) {
	tmpDir := t.TempDir()

	for i := 0; i < 5; i++ {
		f := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))
		os.WriteFile(f, []byte("content"), 0644)
	}

	lc := NewLogCleanup(&CleanupConfig{})
	err := lc.removeDirectoryContents(tmpDir)
	if err != nil {
		t.Errorf("removeDirectoryContents failed: %v", err)
	}

	entries, _ := os.ReadDir(tmpDir)
	if len(entries) != 0 {
		t.Errorf("Expected empty directory, got %d entries", len(entries))
	}
}

func TestLogCleanupClearBashSessionHistory(t *testing.T) {
	lc := NewLogCleanup(&CleanupConfig{DryRun: true})
	lc.clearBashSessionHistory()

	if os.Getenv("HISTCONTROL") != "ignoreboth" {
		t.Error("Expected HISTCONTROL to be set")
	}
}

func TestNetworkEvasionObfuscatePayloadLength(t *testing.T) {
	config := NewDefaultNetworkConfig()
	ne := NewNetworkEvasion(config)

	data := []byte("hello world")
	obfuscated := ne.ObfuscatePayload(data)

	expectedLen := len(data) * 2
	if len(obfuscated) != expectedLen {
		t.Errorf("Expected obfuscated length %d, got %d", expectedLen, len(obfuscated))
	}
}

func TestGenerateRandomDomainLength(t *testing.T) {
	config := NewDefaultNetworkConfig()
	ne := NewNetworkEvasion(config)

	for _, length := range []int{1, 8, 16, 32, 63} {
		domain := ne.GenerateRandomDomain(length)
		if len(domain) != length {
			t.Errorf("Expected length %d, got %d", length, len(domain))
		}
	}
}

func TestNewSyscallManagerDefaultFallbackChain(t *testing.T) {
	sm := NewSyscallManager()
	if len(sm.fallbackChain) != 7 {
		t.Errorf("Expected 7 methods in fallback chain, got %d", len(sm.fallbackChain))
	}
}

func TestAntiAnalysisReportString(t *testing.T) {
	report := &EvasionReport{
		Module: "Test",
		Results: []DetectionResult{
			{Method: "Test1", Detected: true, RiskScore: 0.8, Details: "Found something"},
			{Method: "Test2", Detected: false, RiskScore: 0.0, Details: "Clean"},
		},
		RiskScore: 0.8,
	}

	str := report.String()
	if !strings.Contains(str, "DETECTED") {
		t.Error("Report string should contain DETECTED")
	}
	if !strings.Contains(str, "CLEAN") {
		t.Error("Report string should contain CLEAN")
	}
}
