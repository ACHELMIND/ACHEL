package rootkit

import (
	"runtime"
	"testing"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

func TestNewRootkitEngine(t *testing.T) {
	config := &RootkitConfig{
		Platform:   types.PlatformLinux,
		TargetArch: "x86_64",
		ESPPath:    "/boot/efi",
		BackupPath: "/tmp/rootkit_test_backup",
		Stealth:    true,
		Timeout:    60 * time.Second,
		MaxRetries: 3,
	}

	engine := NewRootkitEngine(config)
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}

	if engine.config.Platform != types.PlatformLinux {
		t.Errorf("expected platform linux, got %s", engine.config.Platform)
	}
}

func TestNewRootkitEngineNilConfig(t *testing.T) {
	engine := NewRootkitEngine(nil)
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}

	if engine.config == nil {
		t.Fatal("expected non-nil default config")
	}
}

func TestGetAvailableTechniques(t *testing.T) {
	engine := NewRootkitEngine(&RootkitConfig{
		Platform: types.PlatformLinux,
	})

	techniques := engine.GetAvailableTechniques()
	if len(techniques) == 0 {
		t.Error("expected available techniques")
	}

	techniqueMap := make(map[RootkitTechnique]bool)
	for _, tech := range techniques {
		techniqueMap[tech] = true
	}

	expectedTechniques := []RootkitTechnique{
		TechniqueDXEDriver,
		TechniqueBootChainHook,
		TechniqueOSLHook,
		TechniqueCMHook,
		TechniqueSecureBootBypass,
		TechniqueMOKEnroll,
		TechniqueSelfReinstall,
		TechniqueESPPersistence,
		TechniqueShimExploit,
		TechniqueHandlerInject,
		TechniqueSMRAMExploit,
		TechniqueROPChain,
		TechniqueInterruptHook,
		TechniqueSPIFlashRead,
		TechniqueSPIFlashWrite,
		TechniqueJTAGDebug,
		TechniqueUARTConsole,
		TechniqueFirmwareEmulation,
	}

	for _, tech := range expectedTechniques {
		if !techniqueMap[tech] {
			t.Errorf("expected technique %s to be available", tech)
		}
	}
}

func TestGetTechniquesByLayer(t *testing.T) {
	engine := NewRootkitEngine(&RootkitConfig{
		Platform: types.PlatformLinux,
	})

	uefiTechniques := engine.GetTechniquesByLayer(LayerUEFI)
	if len(uefiTechniques) != 9 {
		t.Errorf("expected 9 UEFI techniques, got %d", len(uefiTechniques))
	}

	smmTechniques := engine.GetTechniquesByLayer(LayerSMM)
	if len(smmTechniques) != 5 {
		t.Errorf("expected 5 SMM techniques, got %d", len(smmTechniques))
	}

	firmwareTechniques := engine.GetTechniquesByLayer(LayerFirmware)
	if len(firmwareTechniques) != 5 {
		t.Errorf("expected 5 firmware techniques, got %d", len(firmwareTechniques))
	}
}

func TestInstallUnsupportedTechnique(t *testing.T) {
	engine := NewRootkitEngine(&RootkitConfig{
		Platform: types.PlatformLinux,
	})

	_, err := engine.Install("unsupported_technique")
	if err == nil {
		t.Error("expected error for unsupported technique")
	}
}

func TestRemoveUnsupportedTechnique(t *testing.T) {
	engine := NewRootkitEngine(&RootkitConfig{
		Platform: types.PlatformLinux,
	})

	err := engine.Remove("unsupported_technique")
	if err == nil {
		t.Error("expected error for unsupported technique")
	}
}

func TestVerifyUnsupportedTechnique(t *testing.T) {
	engine := NewRootkitEngine(&RootkitConfig{
		Platform: types.PlatformLinux,
	})

	_, err := engine.Verify("unsupported_technique")
	if err == nil {
		t.Error("expected error for unsupported technique")
	}
}

func TestGetInstalled(t *testing.T) {
	engine := NewRootkitEngine(&RootkitConfig{
		Platform: types.PlatformLinux,
	})

	installed := engine.GetInstalled()
	if len(installed) != 0 {
		t.Error("expected no installed techniques")
	}
}

func TestSetFallbackChain(t *testing.T) {
	engine := NewRootkitEngine(&RootkitConfig{
		Platform: types.PlatformLinux,
	})

	newChain := []RootkitLayer{LayerFirmware, LayerSMM, LayerUEFI}
	engine.SetFallbackChain(newChain)

	if len(engine.fallback) != 3 {
		t.Errorf("expected 3 layers in fallback chain, got %d", len(engine.fallback))
	}

	if engine.fallback[0] != LayerFirmware {
		t.Errorf("expected first layer to be firmware, got %s", engine.fallback[0])
	}
}

func TestRootkitConfigDefaults(t *testing.T) {
	config := DefaultRootkitConfig()
	if config == nil {
		t.Fatal("expected non-nil config")
	}

	if config.Platform != types.PlatformLinux {
		t.Errorf("expected platform linux, got %s", config.Platform)
	}

	if config.TargetArch != "x86_64" {
		t.Errorf("expected arch x86_64, got %s", config.TargetArch)
	}

	if config.ESPPath != "/boot/efi" {
		t.Errorf("expected ESP path /boot/efi, got %s", config.ESPPath)
	}
}

func TestRootkitResult(t *testing.T) {
	result := &RootkitResult{
		Success:     true,
		Technique:   TechniqueDXEDriver,
		Layer:       LayerUEFI,
		InstalledAt: time.Now(),
		Details: map[string]string{
			"driver_path": "/boot/efi/EFI/BOOT/BOOTX64.EFI",
		},
	}

	if !result.Success {
		t.Error("expected success to be true")
	}

	if result.Technique != TechniqueDXEDriver {
		t.Errorf("expected technique dxedrvier, got %s", result.Technique)
	}

	if result.Layer != LayerUEFI {
		t.Errorf("expected layer uefi, got %s", result.Layer)
	}
}

func TestFirmwareBackup(t *testing.T) {
	backup := &FirmwareBackup{
		OriginalPath: "/boot/efi/EFI/BOOT/BOOTX64.EFI",
		BackupPath:   "/tmp/backup/BOOTX64.EFI",
		Hash:         "abc123def456",
		Size:         1024,
		CreatedAt:    time.Now(),
	}

	if backup.OriginalPath == "" {
		t.Error("expected non-empty original path")
	}

	if backup.BackupPath == "" {
		t.Error("expected non-empty backup path")
	}
}

func TestUEFIBackup(t *testing.T) {
	backup := &UEFIBackup{
		ESPPath:   "/boot/efi",
		BootPath:  "/boot/efi/EFI/BOOT",
		ShimPath:  "/boot/efi/EFI/ubuntu/shimx64.efi",
		GrubPath:  "/boot/efi/EFI/ubuntu/grubx64.efi",
		MOKPath:   "/boot/efi/MOK.der",
		CreatedAt: time.Now(),
	}

	if backup.ESPPath == "" {
		t.Error("expected non-empty ESP path")
	}
}

func TestSMMRegion(t *testing.T) {
	region := &SMMRegion{
		Start:   0xA0000,
		Size:    0x20000,
		Access:  "rw",
		Modified: true,
	}

	if region.Start != 0xA0000 {
		t.Errorf("expected start 0xA0000, got 0x%x", region.Start)
	}
}

func TestSPIFlashInfo(t *testing.T) {
	info := &SPIFlashInfo{
		ChipID:    "W25Q128",
		VendorID:  "EF40",
		Capacity:  16 * 1024 * 1024,
		BlockSize: 4096,
		Writeable: true,
	}

	if info.ChipID != "W25Q128" {
		t.Errorf("expected chip ID W25Q128, got %s", info.ChipID)
	}
}

func TestJTAGInfo(t *testing.T) {
	info := &JTAGInfo{
		Interface: "JTAG",
		ChainLen:  1,
		Devices:   []string{"ARM Cortex-A53"},
		Speed:     10000,
	}

	if info.ChainLen != 1 {
		t.Errorf("expected chain length 1, got %d", info.ChainLen)
	}
}

func TestFirmwareEmulationConfig(t *testing.T) {
	config := &FirmwareEmulationConfig{
		UEFIFirmwarePath: "/usr/share/OVMF/OVMF_CODE.fd",
		NVRAMPath:        "/tmp/OVMF_VARS.fd",
		MemorySize:       2 * 1024 * 1024 * 1024,
		CPUCores:         2,
		EnableDebug:      true,
	}

	if config.MemorySize != 2*1024*1024*1024 {
		t.Errorf("expected memory size 2GB, got %d", config.MemorySize)
	}
}

func TestRootkitTechniqueConstants(t *testing.T) {
	uefiTechniques := []RootkitTechnique{
		TechniqueDXEDriver,
		TechniqueBootChainHook,
		TechniqueOSLHook,
		TechniqueCMHook,
		TechniqueSecureBootBypass,
		TechniqueMOKEnroll,
		TechniqueSelfReinstall,
		TechniqueESPPersistence,
		TechniqueShimExploit,
	}

	for _, tech := range uefiTechniques {
		if tech == "" {
			t.Error("expected non-empty technique constant")
		}
	}

	smmTechniques := []RootkitTechnique{
		TechniqueHandlerInject,
		TechniqueSMRAMExploit,
		TechniqueROPChain,
		TechniqueInterruptHook,
	}

	for _, tech := range smmTechniques {
		if tech == "" {
			t.Error("expected non-empty technique constant")
		}
	}

	firmwareTechniques := []RootkitTechnique{
		TechniqueSPIFlashRead,
		TechniqueSPIFlashWrite,
		TechniqueJTAGDebug,
		TechniqueUARTConsole,
		TechniqueFirmwareEmulation,
	}

	for _, tech := range firmwareTechniques {
		if tech == "" {
			t.Error("expected non-empty technique constant")
		}
	}
}

func TestRootkitLayerConstants(t *testing.T) {
	layers := []RootkitLayer{
		LayerUEFI,
		LayerSMM,
		LayerFirmware,
	}

	for _, layer := range layers {
		if layer == "" {
			t.Error("expected non-empty layer constant")
		}
	}
}

func TestRootkitMethodInterface(t *testing.T) {
	methods := []RootkitMethod{
		NewDXEDriverMethod(),
		NewBootChainHookMethod(),
		NewOSLHookMethod(),
		NewCMHookMethod(),
		NewSecureBootBypassMethod(),
		NewMOKEnrollMethod(),
		NewUEFISelfReinstallMethod(),
		NewESPPersistenceMethod(),
		NewShimExploitMethod(),
		NewHandlerInjectMethod(),
		NewSMRAMExploitMethod(),
		NewROPChainMethod(),
		NewInterruptHookMethod(),
		NewSMMSelfReinstallMethod(),
		NewSPIFlashReadMethod(),
		NewSPIFlashWriteMethod(),
		NewJTAGDebugMethod(),
		NewUARTConsoleMethod(),
		NewFirmwareEmulationMethod(),
	}

	for _, m := range methods {
		if m.Name() == "" {
			t.Error("expected non-empty method name")
		}

		if m.Layer() == "" {
			t.Error("expected non-empty layer")
		}
	}
}

func TestDXEDriverMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewDXEDriverMethod()
	if method.Name() != "dxedrvier" {
		t.Errorf("expected name dxedrvier, got %s", method.Name())
	}

	if method.Layer() != LayerUEFI {
		t.Errorf("expected layer uefi, got %s", method.Layer())
	}
}

func TestBootChainHookMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewBootChainHookMethod()
	if method.Name() != "boot_chain_hook" {
		t.Errorf("expected name boot_chain_hook, got %s", method.Name())
	}
}

func TestOSLHookMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewOSLHookMethod()
	if method.Name() != "osl_hook" {
		t.Errorf("expected name osl_hook, got %s", method.Name())
	}
}

func TestCMHookMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewCMHookMethod()
	if method.Name() != "cm_hook" {
		t.Errorf("expected name cm_hook, got %s", method.Name())
	}
}

func TestSecureBootBypassMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewSecureBootBypassMethod()
	if method.Name() != "secure_boot_bypass" {
		t.Errorf("expected name secure_boot_bypass, got %s", method.Name())
	}
}

func TestMOKEnrollMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewMOKEnrollMethod()
	if method.Name() != "mok_enroll" {
		t.Errorf("expected name mok_enroll, got %s", method.Name())
	}
}

func TestUEFISelfReinstallMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewUEFISelfReinstallMethod()
	if method.Name() != "self_reinstall" {
		t.Errorf("expected name self_reinstall, got %s", method.Name())
	}
}

func TestESPPersistenceMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewESPPersistenceMethod()
	if method.Name() != "esp_persistence" {
		t.Errorf("expected name esp_persistence, got %s", method.Name())
	}
}

func TestShimExploitMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewShimExploitMethod()
	if method.Name() != "shim_exploit" {
		t.Errorf("expected name shim_exploit, got %s", method.Name())
	}
}

func TestHandlerInjectMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewHandlerInjectMethod()
	if method.Name() != "handler_inject" {
		t.Errorf("expected name handler_inject, got %s", method.Name())
	}

	if method.Layer() != LayerSMM {
		t.Errorf("expected layer smm, got %s", method.Layer())
	}
}

func TestSMRAMExploitMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewSMRAMExploitMethod()
	if method.Name() != "smram_exploit" {
		t.Errorf("expected name smram_exploit, got %s", method.Name())
	}
}

func TestROPChainMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewROPChainMethod()
	if method.Name() != "rop_chain" {
		t.Errorf("expected name rop_chain, got %s", method.Name())
	}
}

func TestInterruptHookMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewInterruptHookMethod()
	if method.Name() != "interrupt_hook" {
		t.Errorf("expected name interrupt_hook, got %s", method.Name())
	}
}

func TestSMMSelfReinstallMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewSMMSelfReinstallMethod()
	if method.Name() != "smm_self_reinstall" {
		t.Errorf("expected name smm_self_reinstall, got %s", method.Name())
	}
}

func TestSPIFlashReadMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewSPIFlashReadMethod()
	if method.Name() != "spi_flash_read" {
		t.Errorf("expected name spi_flash_read, got %s", method.Name())
	}

	if method.Layer() != LayerFirmware {
		t.Errorf("expected layer firmware, got %s", method.Layer())
	}
}

func TestSPIFlashWriteMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewSPIFlashWriteMethod()
	if method.Name() != "spi_flash_write" {
		t.Errorf("expected name spi_flash_write, got %s", method.Name())
	}
}

func TestJTAGDebugMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewJTAGDebugMethod()
	if method.Name() != "jtag_debug" {
		t.Errorf("expected name jtag_debug, got %s", method.Name())
	}
}

func TestUARTConsoleMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewUARTConsoleMethod()
	if method.Name() != "uart_console" {
		t.Errorf("expected name uart_console, got %s", method.Name())
	}
}

func TestFirmwareEmulationMethodInterface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux test on non-Linux platform")
	}

	method := NewFirmwareEmulationMethod()
	if method.Name() != "firmware_emulation" {
		t.Errorf("expected name firmware_emulation, got %s", method.Name())
	}
}
