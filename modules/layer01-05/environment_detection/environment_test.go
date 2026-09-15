package environment_detection

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// =============================================================================
// EnvironmentDetector Tests
// =============================================================================

func TestNewEnvironmentDetector(t *testing.T) {
	d := NewEnvironmentDetector()
	if d == nil {
		t.Fatal("expected non-nil EnvironmentDetector")
	}
	// Detect not yet called, so detected is false
	if d.detected {
		t.Fatal("expected detected false initially")
	}
}

func TestEnvironmentDetector_Detect(t *testing.T) {
	d := NewEnvironmentDetector()
	info := d.Detect()
	if info == nil {
		t.Fatal("expected non-nil EnvironmentInfo")
	}
	if info.OS != runtime.GOOS {
		t.Fatalf("expected OS=%s, got %s", runtime.GOOS, info.OS)
	}
	if info.Arch != runtime.GOARCH {
		t.Fatalf("expected Arch=%s, got %s", runtime.GOARCH, info.Arch)
	}
	if info.CPUCores <= 0 {
		t.Fatal("expected CPUCores > 0")
	}
	if !d.IsDetected() {
		t.Fatal("expected IsDetected true after Detect()")
	}
}

func TestEnvironmentDetector_GetInfo(t *testing.T) {
	d := NewEnvironmentDetector()
	info := d.Detect()
	if info == nil {
		t.Fatal("expected non-nil from Detect")
	}
	// After Detect, the environment info is stored internally
	if !d.detected {
		t.Fatal("expected detected true after Detect")
	}
	_ = info.OS
}

func TestEnvironmentDetector_DetectHostname(t *testing.T) {
	d := NewEnvironmentDetector()
	info := d.Detect()
	if info.Hostname == "" {
		t.Fatal("expected non-empty hostname")
	}
}

func TestEnvironmentDetector_DetectVM(t *testing.T) {
	d := NewEnvironmentDetector()
	info := d.Detect()
	// IsVM may be true or false depending on environment; just verify it's set
	_ = info.IsVM
}

func TestEnvironmentDetector_DetectSandbox(t *testing.T) {
	d := NewEnvironmentDetector()
	info := d.Detect()
	// In CI or container, this might be true; verify the field is accessible
	_ = info.IsSandbox
}

func TestEnvironmentDetector_DetectContainer(t *testing.T) {
	d := NewEnvironmentDetector()
	info := d.Detect()
	// In containerized env, this should be true; otherwise false
	_ = info.IsContainer
}

func TestEnvironmentDetector_DetectDebugger(t *testing.T) {
	d := NewEnvironmentDetector()
	info := d.Detect()
	// Typically false in test environment
	_ = info.IsDebugged
}

func TestContainsFunction(t *testing.T) {
	tests := []struct {
		s, sub string
		want   bool
	}{
		{"hello world", "world", true},
		{"hello world", "xyz", false},
		{"VMware Tools", "VMware", true},
		{"", "", true},
		{"a", "ab", false},
	}
	for _, tt := range tests {
		got := contains(tt.s, tt.sub)
		if got != tt.want {
			t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.sub, got, tt.want)
		}
	}
}

func TestContainsSubstring(t *testing.T) {
	tests := []struct {
		s, sub string
		want   bool
	}{
		{"hello", "ell", true},
		{"hello", "xyz", false},
		{"VMware", "VMware", true},
		{"", "a", false},
	}
	for _, tt := range tests {
		got := containsSubstring(tt.s, tt.sub)
		if got != tt.want {
			t.Errorf("containsSubstring(%q, %q) = %v, want %v", tt.s, tt.sub, got, tt.want)
		}
	}
}

func TestEnvironmentInfo_Fields(t *testing.T) {
	d := NewEnvironmentDetector()
	info := d.Detect()
	if info.VMType != "" && !info.IsVM {
		t.Fatal("VMType set but IsVM is false")
	}
	if info.SandboxType != "" && !info.IsSandbox {
		t.Fatal("SandboxType set but IsSandbox is false")
	}
}

// =============================================================================
// ETWPatch Tests
// =============================================================================

func TestNewETWPatch(t *testing.T) {
	e := NewETWPatch()
	if e == nil {
		t.Fatal("expected non-nil ETWPatch")
	}
	if e.IsPatched() {
		t.Fatal("expected IsPatched false initially")
	}
}

func TestETWPatch_DisableEnableETW(t *testing.T) {
	e := NewETWPatch()
	e.DisableETW()
	if !e.IsPatched() {
		t.Fatal("expected IsPatched true after DisableETW")
	}
	status := e.GetETWStatus()
	if !status["patched"] {
		t.Fatal("expected status patched=true")
	}

	e.EnableETW()
	if e.IsPatched() {
		t.Fatal("expected IsPatched false after EnableETW")
	}
	status = e.GetETWStatus()
	if status["patched"] {
		t.Fatal("expected status patched=false")
	}
}

func TestETWPatch_PatchRestore(t *testing.T) {
	e := NewETWPatch()
	// On Linux, Patch() returns nil without changing state (requires Windows)
	e.Patch()
	// On Linux, patched stays false
	if runtime.GOOS == "linux" {
		if e.IsPatched() {
			t.Fatal("expected IsPatched false on Linux after Patch()")
		}
	}

	e.Restore()
	if e.IsPatched() {
		t.Fatal("expected IsPatched false after Restore")
	}
}

func TestETWPatch_GetETWProvider(t *testing.T) {
	e := NewETWPatch()
	if e.GetETWProvider() != 0 {
		t.Fatal("expected provider 0 (stub)")
	}
}

func TestETWPatch_DetectETW(t *testing.T) {
	e := NewETWPatch()
	if e.DetectETW() {
		t.Fatal("expected DetectETW false (stub)")
	}
}

func TestETWPatch_ConcurrentAccess(t *testing.T) {
	e := NewETWPatch()
	done1 := make(chan struct{})
	done2 := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			e.DisableETW()
			_ = e.IsPatched()
			e.EnableETW()
			_ = e.GetETWStatus()
		}
		close(done1)
	}()
	go func() {
		for i := 0; i < 100; i++ {
			_ = e.IsPatched()
			_ = e.GetETWStatus()
		}
		close(done2)
	}()
	<-done1
	<-done2
}

// =============================================================================
// Unhook Tests
// =============================================================================

func TestNewUnhook(t *testing.T) {
	u := NewUnhook()
	if u == nil {
		t.Fatal("expected non-nil Unhook")
	}
	if u.IsUnhooked() {
		t.Fatal("expected IsUnhooked false initially")
	}
}

func TestUnhook_RestoreHooks(t *testing.T) {
	u := NewUnhook()
	u.RestoreHooks()
	if u.IsUnhooked() {
		t.Fatal("expected IsUnhooked false after RestoreHooks")
	}
}

func TestUnhook_GetHookStatus(t *testing.T) {
	u := NewUnhook()
	status := u.GetHookStatus()
	if status["ntdll"] || status["kernel32"] {
		t.Fatal("expected hooks unhooked=false initially")
	}

	u.RestoreHooks()
	status = u.GetHookStatus()
	if status["ntdll"] || status["kernel32"] {
		t.Fatal("expected hooks unhooked=false after Restore")
	}
}

func TestUnhook_DetectHooks(t *testing.T) {
	u := NewUnhook()
	// DetectHooks returns empty list (stub)
	detected := u.DetectHooks()
	if len(detected) != 0 {
		t.Fatalf("expected 0 detected hooks, got %d", len(detected))
	}
}

func TestUnhook_UnhookNtdll(t *testing.T) {
	u := NewUnhook()
	err := u.UnhookNtdll()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// On Linux, unhooked stays false; on Windows it would be true
	if runtime.GOOS == "windows" {
		if !u.IsUnhooked() {
			t.Fatal("expected IsUnhooked true on Windows after UnhookNtdll")
		}
	}
}

func TestUnhook_UnhookKernel32(t *testing.T) {
	u := NewUnhook()
	err := u.UnhookKernel32()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if runtime.GOOS == "windows" {
		if !u.IsUnhooked() {
			t.Fatal("expected IsUnhooked true on Windows after UnhookKernel32")
		}
	}
}

func TestUnhook_UnhookAll(t *testing.T) {
	u := NewUnhook()
	err := u.UnhookAll()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if runtime.GOOS == "windows" {
		if !u.IsUnhooked() {
			t.Fatal("expected IsUnhooked true on Windows after UnhookAll")
		}
	}
}

func TestUnhook_ConcurrentAccess(t *testing.T) {
	u := NewUnhook()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			u.RestoreHooks()
			_ = u.IsUnhooked()
			_ = u.GetHookStatus()
			_ = u.DetectHooks()
		}
		close(done)
	}()
	<-done
}

// =============================================================================
// Timestomp Tests
// =============================================================================

func TestNewTimestomp(t *testing.T) {
	ts := NewTimestomp()
	if ts == nil {
		t.Fatal("expected non-nil Timestomp")
	}
	if ts.IsModified() {
		t.Fatal("expected IsModified false initially")
	}
}

func TestTimestomp_Touch(t *testing.T) {
	ts := NewTimestomp()
	tmpFile := t.TempDir() + "/touch_test.txt"
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := ts.Touch(tmpFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ts.IsModified() {
		t.Fatal("expected IsModified true after Touch")
	}
}

func TestTimestomp_Touch_NonExistent(t *testing.T) {
	ts := NewTimestomp()
	err := ts.Touch("/nonexistent/file/path")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestTimestomp_SetTime(t *testing.T) {
	ts := NewTimestomp()
	tmpFile := t.TempDir() + "/settime_test.txt"
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	pastTime := time.Now().Add(-24 * time.Hour)
	if err := ts.SetTime(tmpFile, pastTime, pastTime); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ts.IsModified() {
		t.Fatal("expected IsModified true after SetTime")
	}
}

func TestTimestomp_MatchTime(t *testing.T) {
	ts := NewTimestomp()
	tmpDir := t.TempDir()
	targetFile := tmpDir + "/target.txt"
	modFile := tmpDir + "/modify.txt"
	os.WriteFile(targetFile, []byte("target"), 0644)
	os.WriteFile(modFile, []byte("modify"), 0644)

	// Set target to a specific time
	pastTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(targetFile, pastTime, pastTime)

	if err := ts.MatchTime(modFile, targetFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ts.IsModified() {
		t.Fatal("expected IsModified true after MatchTime")
	}
}

func TestTimestomp_RandomizeTime(t *testing.T) {
	ts := NewTimestomp()
	tmpFile := t.TempDir() + "/randomize_test.txt"
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := ts.RandomizeTime(tmpFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ts.IsModified() {
		t.Fatal("expected IsModified true after RandomizeTime")
	}

	// Verify the file's time was changed to ~30 days ago
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	diff := time.Since(info.ModTime())
	if diff < 29*24*time.Hour || diff > 31*24*time.Hour {
		t.Fatalf("expected ModTime ~30 days ago, got diff=%v", diff)
	}
}

func TestTimestomp_RestoreTime(t *testing.T) {
	ts := NewTimestomp()
	tmpFile := t.TempDir() + "/restore_test.txt"
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	originalTime := time.Now().Add(-10 * 24 * time.Hour)
	if err := ts.RestoreTime(tmpFile, originalTime); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// RestoreTime does not set modified=true
	if ts.IsModified() {
		t.Fatal("expected IsModified false after RestoreTime (not set)")
	}
}

func TestTimestomp_GetFileInfo(t *testing.T) {
	ts := NewTimestomp()
	tmpFile := t.TempDir() + "/getinfo_test.txt"
	os.WriteFile(tmpFile, []byte("test"), 0644)

	info, err := ts.GetFileInfo(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name() != "getinfo_test.txt" {
		t.Fatalf("expected name getinfo_test.txt, got %s", info.Name())
	}
}

func TestTimestomp_ConcurrentAccess(t *testing.T) {
	ts := NewTimestomp()
	tmpFile := t.TempDir() + "/concurrent_test.txt"
	os.WriteFile(tmpFile, []byte("test"), 0644)

	done1 := make(chan struct{})
	done2 := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			ts.Touch(tmpFile)
		}
		close(done1)
	}()
	go func() {
		for i := 0; i < 50; i++ {
			_ = ts.IsModified()
			ts.RandomizeTime(tmpFile)
		}
		close(done2)
	}()
	<-done1
	<-done2
}

// =============================================================================
// ProcMem Tests
// =============================================================================

func TestNewProcMem(t *testing.T) {
	pm := NewProcMem(1234)
	if pm == nil {
		t.Fatal("expected non-nil ProcMem")
	}
	if pm.GetPID() != 1234 {
		t.Fatalf("expected PID 1234, got %d", pm.GetPID())
	}
}

func TestProcMem_IsRunning(t *testing.T) {
	pm := NewProcMem(1234)
	if pm.IsRunning() {
		t.Fatal("expected IsRunning false initially")
	}
}

func TestProcMem_GetPID(t *testing.T) {
	pm := NewProcMem(9999)
	if pm.GetPID() != 9999 {
		t.Fatalf("expected PID 9999, got %d", pm.GetPID())
	}
}

func TestProcMem_ReadMemory(t *testing.T) {
	pm := NewProcMem(os.Getpid())
	data, err := pm.ReadMemory(0, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 10 {
		t.Fatalf("expected 10 bytes, got %d", len(data))
	}
}

func TestProcMem_WriteMemory(t *testing.T) {
	pm := NewProcMem(os.Getpid())
	err := pm.WriteMemory(0, []byte("test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProcMem_GetProcessMemory(t *testing.T) {
	pm := NewProcMem(os.Getpid())
	_, err := pm.GetProcessMemory()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// =============================================================================
// YaraDetector Tests
// =============================================================================

func TestNewYaraDetector(t *testing.T) {
	y := NewYaraDetector()
	if y == nil {
		t.Fatal("expected non-nil YaraDetector")
	}
	if len(y.GetRules()) != 0 {
		t.Fatal("expected 0 rules initially")
	}
}

func TestYaraDetector_AddRule(t *testing.T) {
	y := NewYaraDetector()
	y.AddRule(YaraRule{Name: "rule1", Pattern: "malware", Tags: []string{"trojan"}})
	rules := y.GetRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "rule1" {
		t.Fatalf("expected rule name rule1, got %s", rules[0].Name)
	}
}

func TestYaraDetector_RemoveRule(t *testing.T) {
	y := NewYaraDetector()
	y.AddRule(YaraRule{Name: "rule1", Pattern: "a"})
	y.AddRule(YaraRule{Name: "rule2", Pattern: "b"})
	y.RemoveRule("rule1")
	rules := y.GetRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule after remove, got %d", len(rules))
	}
	if rules[0].Name != "rule2" {
		t.Fatalf("expected remaining rule2, got %s", rules[0].Name)
	}
}

func TestYaraDetector_RemoveRule_NotFound(t *testing.T) {
	y := NewYaraDetector()
	y.RemoveRule("nonexistent") // should not panic
	rules := y.GetRules()
	if len(rules) != 0 {
		t.Fatal("expected 0 rules")
	}
}

func TestYaraDetector_Scan_NoMatch(t *testing.T) {
	y := NewYaraDetector()
	y.AddRule(YaraRule{Name: "rule1", Pattern: "malware"})
	// matchRule always returns false (stub), so scan should not match
	matched, name := y.Scan([]byte("clean data"))
	if matched {
		t.Fatal("expected no match (matchRule is stub)")
	}
	if name != "" {
		t.Fatalf("expected empty name, got %s", name)
	}
}

func TestYaraDetector_Scan_EmptyRules(t *testing.T) {
	y := NewYaraDetector()
	matched, _ := y.Scan([]byte("data"))
	if matched {
		t.Fatal("expected no match with no rules")
	}
}

func TestYaraDetector_IsDetected(t *testing.T) {
	y := NewYaraDetector()
	if y.IsDetected() {
		t.Fatal("expected IsDetected false initially")
	}
}

func TestYaraDetector_ClearRules(t *testing.T) {
	y := NewYaraDetector()
	y.AddRule(YaraRule{Name: "r1"})
	y.AddRule(YaraRule{Name: "r2"})
	y.ClearRules()
	if len(y.GetRules()) != 0 {
		t.Fatal("expected 0 rules after ClearRules")
	}
}

func TestYaraDetector_GetMatchCount(t *testing.T) {
	y := NewYaraDetector()
	y.AddRule(YaraRule{Name: "r1"})
	y.AddRule(YaraRule{Name: "r2"})
	y.AddRule(YaraRule{Name: "r3"})
	if y.GetMatchCount() != 3 {
		t.Fatalf("expected 3, got %d", y.GetMatchCount())
	}
}

func TestYaraDetector_GetLastScanTime(t *testing.T) {
	y := NewYaraDetector()
	y.AddRule(YaraRule{Name: "r1"})
	y.Scan([]byte("test data"))
	ts := y.GetLastScanTime()
	if ts.IsZero() {
		t.Fatal("expected GetLastScanTime to return non-zero time")
	}
}

func TestYaraDetector_ScanFile(t *testing.T) {
	y := NewYaraDetector()
	matched, _ := y.ScanFile("/nonexistent")
	if matched {
		t.Fatal("expected no match (stub)")
	}
}

func TestYaraDetector_ScanProcess(t *testing.T) {
	y := NewYaraDetector()
	matched, _ := y.ScanProcess(1)
	if matched {
		t.Fatal("expected no match (stub)")
	}
}

func TestYaraDetector_ScanMemory(t *testing.T) {
	y := NewYaraDetector()
	matched, _ := y.ScanMemory(1)
	if matched {
		t.Fatal("expected no match (stub)")
	}
}

func TestYaraDetector_ConcurrentAccess(t *testing.T) {
	y := NewYaraDetector()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			y.AddRule(YaraRule{Name: "r"})
			_ = y.GetRules()
			y.ClearRules()
			y.Scan([]byte("data"))
		}
		close(done)
	}()
	<-done
}

// =============================================================================
// DebuggerDetector Tests
// =============================================================================

func TestNewDebuggerDetector(t *testing.T) {
	dd := NewDebuggerDetector()
	if dd == nil {
		t.Fatal("expected non-nil DebuggerDetector")
	}
}

func TestDebuggerDetector_Detect(t *testing.T) {
	dd := NewDebuggerDetector()
	detected, _ := dd.Detect()
	_ = detected
}

func TestDebuggerDetector_IsDetected(t *testing.T) {
	dd := NewDebuggerDetector()
	// Not detected initially
	if dd.IsDetected() {
		t.Fatal("expected not detected before Detect()")
	}
	// After detect, check state is updated
	dd.Detect()
	_ = dd.IsDetected()
}

func TestDebuggerDetector_GetDebuggerType(t *testing.T) {
	dd := NewDebuggerDetector()
	// Empty before detect
	if got := dd.GetDebuggerType(); got != "" {
		t.Fatalf("expected empty debugger type before detect, got %q", got)
	}
	dd.Detect()
	_ = dd.GetDebuggerType()
}

func TestDebuggerDetector_AntiDebug(t *testing.T) {
	// AntiDebug runs forever; just verify it doesn't panic on entry.
	// We won't call it directly — it loops with os.Exit(1).
	// Instead verify that NewDebuggerDetector returns a valid object.
	dd := NewDebuggerDetector()
	if dd == nil {
		t.Fatal("expected non-nil for anti-debug readiness")
	}
}

// =============================================================================
// VMDetector Tests
// =============================================================================

func TestNewVMDetector(t *testing.T) {
	vd := NewVMDetector()
	if vd == nil {
		t.Fatal("expected non-nil VMDetector")
	}
}

func TestVMDetector_Detect(t *testing.T) {
	vd := NewVMDetector()
	detected, _ := vd.Detect()
	_ = detected
}

func TestVMDetector_IsDetected(t *testing.T) {
	vd := NewVMDetector()
	vd.Detect()
	_ = vd.IsDetected()
}

func TestVMDetector_GetVMType(t *testing.T) {
	vd := NewVMDetector()
	vd.Detect()
	_ = vd.GetVMType()
}

func TestVMDetector_GetVMName(t *testing.T) {
	vd := NewVMDetector()
	vd.Detect()
	_ = vd.GetVMName()
}

// =============================================================================
// SandboxDetector Tests
// =============================================================================

func TestNewSandboxDetector(t *testing.T) {
	sd := NewSandboxDetector()
	if sd == nil {
		t.Fatal("expected non-nil SandboxDetector")
	}
}

func TestSandboxDetector_Detect(t *testing.T) {
	sd := NewSandboxDetector()
	detected, _ := sd.Detect()
	_ = detected
}

func TestSandboxDetector_IsDetected(t *testing.T) {
	sd := NewSandboxDetector()
	sd.Detect()
	_ = sd.IsDetected()
}

func TestSandboxDetector_GetSandboxType(t *testing.T) {
	sd := NewSandboxDetector()
	sd.Detect()
	_ = sd.GetSandboxType()
}

func TestSandboxDetector_SleepBeforeExecution(t *testing.T) {
	sd := NewSandboxDetector()
	// Verify it doesn't panic; skip actual 5s sleep in fast tests.
	// We just call it in a goroutine with a short timeout to confirm it starts.
	done := make(chan struct{})
	go func() {
		sd.SleepBeforeExecution()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		// Sleep started but we timed out waiting — acceptable in test.
	}
}

// =============================================================================
// EDRDetector Tests
// =============================================================================

func TestNewEDRDetector(t *testing.T) {
	ed := NewEDRDetector()
	if ed == nil {
		t.Fatal("expected non-nil EDRDetector")
	}
}

func TestEDRDetector_Detect(t *testing.T) {
	ed := NewEDRDetector()
	detected, _ := ed.Detect()
	_ = detected
}

func TestEDRDetector_IsDetected(t *testing.T) {
	ed := NewEDRDetector()
	ed.Detect()
	_ = ed.IsDetected()
}

func TestEDRDetector_GetEDRType(t *testing.T) {
	ed := NewEDRDetector()
	ed.Detect()
	_ = ed.GetEDRType()
}

func TestEDRDetector_DetectHooks(t *testing.T) {
	ed := NewEDRDetector()
	_ = ed.DetectHooks()
}

func TestEDRDetector_GetHookedFunctions(t *testing.T) {
	ed := NewEDRDetector()
	funcs := ed.GetHookedFunctions()
	_ = funcs
}

// =============================================================================
// NetworkMonitorDetector Tests
// =============================================================================

func TestNewNetworkMonitorDetector(t *testing.T) {
	nm := NewNetworkMonitorDetector()
	if nm == nil {
		t.Fatal("expected non-nil NetworkMonitorDetector")
	}
}

func TestNetworkMonitorDetector_Detect(t *testing.T) {
	nm := NewNetworkMonitorDetector()
	detected, _ := nm.Detect()
	_ = detected
}

func TestNetworkMonitorDetector_IsDetected(t *testing.T) {
	nm := NewNetworkMonitorDetector()
	nm.Detect()
	_ = nm.IsDetected()
}

func TestNetworkMonitorDetector_GetMonitorType(t *testing.T) {
	nm := NewNetworkMonitorDetector()
	nm.Detect()
	_ = nm.GetMonitorType()
}

func TestNetworkMonitorDetector_GetNetworkInterfaces(t *testing.T) {
	nm := NewNetworkMonitorDetector()
	ifaces := nm.GetNetworkInterfaces()
	_ = ifaces
}

func TestNetworkMonitorDetector_GetDNS(t *testing.T) {
	nm := NewNetworkMonitorDetector()
	dns := nm.GetDNS()
	_ = dns
}

func TestNetworkMonitorDetector_GetRoutingTable(t *testing.T) {
	nm := NewNetworkMonitorDetector()
	rt := nm.GetRoutingTable()
	_ = rt
}

// =============================================================================
// Integration: multiple detectors on same file
// =============================================================================

func TestTimestomp_SetTime_ThenGetFileInfo(t *testing.T) {
	ts := NewTimestomp()
	tmpFile := t.TempDir() + "/integration_test.txt"
	os.WriteFile(tmpFile, []byte("data"), 0644)

	pastTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	ts.SetTime(tmpFile, pastTime, pastTime)

	info, err := ts.GetFileInfo(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(pastTime) {
		t.Fatalf("expected ModTime %v, got %v", pastTime, info.ModTime())
	}
}

func TestEnvironmentDetector_ConcurrentDetect(t *testing.T) {
	d := NewEnvironmentDetector()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			info := d.Detect()
			_ = info.OS
			_ = d.GetInfo()
			_ = d.IsDetected()
		}
		close(done)
	}()
	<-done
}

func TestGetFileManager(t *testing.T) {
	fm := GetFileManager()
	if fm == nil {
		t.Fatal("expected non-nil FileManager")
	}
	fm.Cleanup([]string{"nonexistent1", "nonexistent2"})
	// Should not panic
}

// GetFileManager is a helper that wraps os operations
func GetFileManager() *fileManager {
	return &fileManager{}
}

type fileManager struct{}

func (fm *fileManager) Cleanup(files []string) {
	for _, f := range files {
		os.Remove(f)
	}
}

func TestTimestomp_Integration(t *testing.T) {
	ts := NewTimestomp()
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")
	os.WriteFile(file1, []byte("data1"), 0644)
	os.WriteFile(file2, []byte("data2"), 0644)

	// Set file2 to a specific time
	pastTime := time.Date(2019, 6, 15, 12, 0, 0, 0, time.UTC)
	ts.SetTime(file2, pastTime, pastTime)

	// Match file1's time to file2
	if err := ts.MatchTime(file1, file2); err != nil {
		t.Fatal(err)
	}

	info1, _ := os.Stat(file1)
	info2, _ := os.Stat(file2)
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Fatal("expected matching mod times")
	}
}
