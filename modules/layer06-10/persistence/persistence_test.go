package persistence

import (
	"runtime"
	"testing"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

func TestNewPersistenceEngine(t *testing.T) {
	config := &PersistenceConfig{
		Platform:   types.PlatformLinux,
		AgentPath:  "/tmp/test_agent",
		AgentArgs:  "--daemon",
		Priority:   1,
		Stealth:    false,
		Timeout:    30 * time.Second,
		RetryCount: 3,
		RetryDelay: 5 * time.Second,
	}

	engine := NewPersistenceEngine(config)
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}

	if engine.config.Platform != types.PlatformLinux {
		t.Errorf("expected platform linux, got %s", engine.config.Platform)
	}
}

func TestNewPersistenceEngineNilConfig(t *testing.T) {
	engine := NewPersistenceEngine(nil)
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}

	if engine.config == nil {
		t.Fatal("expected non-nil default config")
	}
}

func TestGetAvailableMethods(t *testing.T) {
	engine := NewPersistenceEngine(&PersistenceConfig{
		Platform: types.PlatformLinux,
	})

	methods := engine.GetAvailableMethods()
	if len(methods) == 0 {
		t.Error("expected available methods")
	}

	methodMap := make(map[PersistenceMethod]bool)
	for _, m := range methods {
		methodMap[m] = true
	}

	expectedMethods := []PersistenceMethod{
		MethodCronJob,
		MethodSystemdService,
		MethodRCLocal,
		MethodProfileScript,
		MethodBashrc,
		MethodSSHKeys,
		MethodPAMModule,
		MethodUdevRule,
		MethodInitramfsHook,
	}

	for _, m := range expectedMethods {
		if !methodMap[m] {
			t.Errorf("expected method %s to be available", m)
		}
	}
}

func TestGetAvailableMethodsWindows(t *testing.T) {
	engine := NewPersistenceEngine(&PersistenceConfig{
		Platform: types.PlatformWindows,
	})

	methods := engine.GetAvailableMethods()
	if len(methods) != 11 {
		t.Errorf("expected 11 Windows methods, got %d", len(methods))
	}
}

func TestGetAvailableMethodsDarwin(t *testing.T) {
	engine := NewPersistenceEngine(&PersistenceConfig{
		Platform: types.PlatformDarwin,
	})

	methods := engine.GetAvailableMethods()
	if len(methods) != 6 {
		t.Errorf("expected 6 Darwin methods, got %d", len(methods))
	}
}

func TestGetAvailableMethodsAndroid(t *testing.T) {
	engine := NewPersistenceEngine(&PersistenceConfig{
		Platform: types.PlatformAndroid,
	})

	methods := engine.GetAvailableMethods()
	if len(methods) != 5 {
		t.Errorf("expected 5 Android methods, got %d", len(methods))
	}
}

func TestInstallUnsupportedMethod(t *testing.T) {
	engine := NewPersistenceEngine(&PersistenceConfig{
		Platform: types.PlatformLinux,
	})

	params := &PersistenceParams{
		Method:    "unsupported_method",
		AgentPath: "/tmp/test",
	}

	_, err := engine.Install("unsupported_method", params)
	if err == nil {
		t.Error("expected error for unsupported method")
	}
}

func TestRemoveUnsupportedMethod(t *testing.T) {
	engine := NewPersistenceEngine(&PersistenceConfig{
		Platform: types.PlatformLinux,
	})

	params := &PersistenceParams{
		Method:    "unsupported_method",
		AgentPath: "/tmp/test",
	}

	err := engine.Remove("unsupported_method", params)
	if err == nil {
		t.Error("expected error for unsupported method")
	}
}

func TestVerifyUnsupportedMethod(t *testing.T) {
	engine := NewPersistenceEngine(&PersistenceConfig{
		Platform: types.PlatformLinux,
	})

	_, err := engine.Verify("unsupported_method")
	if err == nil {
		t.Error("expected error for unsupported method")
	}
}

func TestGetInstalled(t *testing.T) {
	engine := NewPersistenceEngine(&PersistenceConfig{
		Platform: types.PlatformLinux,
	})

	installed := engine.GetInstalled()
	if len(installed) != 0 {
		t.Error("expected no installed methods")
	}
}

func TestPersistenceConfigDefaults(t *testing.T) {
	config := DefaultPersistenceConfig()
	if config == nil {
		t.Fatal("expected non-nil config")
	}

	if config.Platform != types.PlatformWindows {
		t.Errorf("expected windows platform, got %s", config.Platform)
	}

	if config.AgentPath != "/tmp/agent" {
		t.Errorf("expected agent path /tmp/agent, got %s", config.AgentPath)
	}
}

func TestWatchdogConfigDefaults(t *testing.T) {
	config := DefaultWatchdogConfig()
	if config == nil {
		t.Fatal("expected non-nil config")
	}

	if config.Interval != 60*time.Second {
		t.Errorf("expected interval 60s, got %v", config.Interval)
	}

	if !config.AutoRepair {
		t.Error("expected auto repair enabled")
	}
}

func TestPersistenceParams(t *testing.T) {
	params := &PersistenceParams{
		Method:      MethodCronJob,
		AgentPath:   "/tmp/agent",
		AgentArgs:   "--daemon",
		Name:        "test_persistence",
		Description: "Test persistence method",
		Extra: map[string]string{
			"key": "value",
		},
	}

	if params.Method != MethodCronJob {
		t.Errorf("expected method cron_job, got %s", params.Method)
	}

	if params.AgentPath != "/tmp/agent" {
		t.Errorf("expected agent path /tmp/agent, got %s", params.AgentPath)
	}
}

func TestPersistenceResult(t *testing.T) {
	result := &PersistenceResult{
		Success:     true,
		Method:      MethodCronJob,
		InstalledAt: time.Now(),
		Details: map[string]string{
			"cron_line": "@reboot /tmp/agent",
		},
	}

	if !result.Success {
		t.Error("expected success to be true")
	}

	if result.Method != MethodCronJob {
		t.Errorf("expected method cron_job, got %s", result.Method)
	}
}

func TestWatchdogEvent(t *testing.T) {
	event := WatchdogEvent{
		Type:      "repaired",
		Method:    MethodCronJob,
		Status:    "repaired",
		Timestamp: time.Now(),
		Details: map[string]string{
			"status": "repaired",
		},
	}

	if event.Type != "repaired" {
		t.Errorf("expected type repaired, got %s", event.Type)
	}

	if event.Method != MethodCronJob {
		t.Errorf("expected method cron_job, got %s", event.Method)
	}
}

func TestLinuxCronJobMethod(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewLinuxCronJobMethod()
	if method.Name() != "cron_job" {
		t.Errorf("expected name cron_job, got %s", method.Name())
	}

	if method.Platform() != types.PlatformLinux {
		t.Errorf("expected platform linux, got %s", method.Platform())
	}

	if method.RequiresElevation() {
		t.Error("expected cron job to not require elevation")
	}
}

func TestLinuxSystemdServiceMethod(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewSystemdServiceMethod()
	if method.Name() != "systemd_service" {
		t.Errorf("expected name systemd_service, got %s", method.Name())
	}

	if !method.RequiresElevation() {
		t.Error("expected systemd service to require elevation")
	}
}

func TestLinuxRCLocalMethod(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewRCLocalMethod()
	if method.Name() != "rc_local" {
		t.Errorf("expected name rc_local, got %s", method.Name())
	}

	if !method.RequiresElevation() {
		t.Error("expected rc.local to require elevation")
	}
}

func TestLinuxProfileScriptMethod(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewProfileScriptMethod()
	if method.Name() != "profile_script" {
		t.Errorf("expected name profile_script, got %s", method.Name())
	}

	if method.RequiresElevation() {
		t.Error("expected profile script to not require elevation")
	}
}

func TestLinuxBashrcMethod(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewBashrcMethod()
	if method.Name() != "bashrc" {
		t.Errorf("expected name bashrc, got %s", method.Name())
	}

	if method.RequiresElevation() {
		t.Error("expected bashrc to not require elevation")
	}
}

func TestLinuxSSHKeysMethod(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewLinuxSSHKeysMethod()
	if method.Name() != "ssh_keys" {
		t.Errorf("expected name ssh_keys, got %s", method.Name())
	}

	if method.RequiresElevation() {
		t.Error("expected SSH keys to not require elevation")
	}
}

func TestLinuxPAMModuleMethod(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewPAMModuleMethod()
	if method.Name() != "pam_module" {
		t.Errorf("expected name pam_module, got %s", method.Name())
	}

	if !method.RequiresElevation() {
		t.Error("expected PAM module to require elevation")
	}
}

func TestLinuxUdevRuleMethod(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewUdevRuleMethod()
	if method.Name() != "udev_rule" {
		t.Errorf("expected name udev_rule, got %s", method.Name())
	}

	if !method.RequiresElevation() {
		t.Error("expected udev rule to require elevation")
	}
}

func TestLinuxInitramfsHookMethod(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewInitramfsHookMethod()
	if method.Name() != "initramfs_hook" {
		t.Errorf("expected name initramfs_hook, got %s", method.Name())
	}

	if !method.RequiresElevation() {
		t.Error("expected initramfs hook to require elevation")
	}
}

func TestPersistenceMethodConstants(t *testing.T) {
	windowsMethods := []PersistenceMethod{
		MethodRegistryRun,
		MethodScheduledTask,
		MethodServiceInstall,
		MethodWMIEvent,
		MethodStartupFolder,
		MethodADS,
		MethodDLLSideload,
		MethodCOMHijack,
		MethodAppInit,
		MethodIFEO,
		MethodAccessibility,
	}

	for _, m := range windowsMethods {
		if m == "" {
			t.Error("expected non-empty method constant")
		}
	}

	linuxMethods := []PersistenceMethod{
		MethodCronJob,
		MethodSystemdService,
		MethodRCLocal,
		MethodProfileScript,
		MethodBashrc,
		MethodSSHKeys,
		MethodPAMModule,
		MethodUdevRule,
		MethodInitramfsHook,
	}

	for _, m := range linuxMethods {
		if m == "" {
			t.Error("expected non-empty method constant")
		}
	}

	darwinMethods := []PersistenceMethod{
		MethodLaunchDaemon,
		MethodLaunchAgent,
		MethodDarwinCronJob,
		MethodDarwinSSHKeys,
		MethodLoginItem,
		MethodKernelExtension,
	}

	for _, m := range darwinMethods {
		if m == "" {
			t.Error("expected non-empty method constant")
		}
	}

	androidMethods := []PersistenceMethod{
		MethodMagiskModule,
		MethodBootCompleted,
		MethodForegroundService,
		MethodDeviceAdmin,
		MethodAndroidAccessibility,
	}

	for _, m := range androidMethods {
		if m == "" {
			t.Error("expected non-empty method constant")
		}
	}
}

func TestPersistenceMethodInterface(t *testing.T) {
	methods := []PersistenceMethodInterface{
		NewRegistryRunMethod(),
		NewScheduledTaskMethod(),
		NewServiceInstallMethod(),
		NewWMIEventMethod(),
		NewStartupFolderMethod(),
		NewADSMethod(),
		NewDLLSideloadMethod(),
		NewCOMHijackMethod(),
		NewAppInitMethod(),
		NewIFEOMethod(),
		NewAccessibilityMethod(),
		NewLinuxCronJobMethod(),
		NewSystemdServiceMethod(),
		NewRCLocalMethod(),
		NewProfileScriptMethod(),
		NewBashrcMethod(),
		NewLinuxSSHKeysMethod(),
		NewPAMModuleMethod(),
		NewUdevRuleMethod(),
		NewInitramfsHookMethod(),
		NewLaunchDaemonMethod(),
		NewLaunchAgentMethod(),
		NewDarwinCronJobMethod(),
		NewDarwinSSHKeysMethod(),
		NewLoginItemMethod(),
		NewKernelExtensionMethod(),
		NewMagiskModuleMethod(),
		NewBootCompletedMethod(),
		NewForegroundServiceMethod(),
		NewDeviceAdminMethod(),
		NewAndroidAccessibilityMethod(),
	}

	for _, m := range methods {
		if m.Name() == "" {
			t.Error("expected non-empty method name")
		}

		if m.Platform() == "" {
			t.Error("expected non-empty platform")
		}
	}
}
