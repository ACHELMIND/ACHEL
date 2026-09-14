package lateral

import (
	"testing"
	"time"
)

func TestLateralEngineCreation(t *testing.T) {
	engine := NewLateralEngine(nil)
	if engine == nil {
		t.Fatal("Expected non-nil engine")
	}
	if engine.config == nil {
		t.Fatal("Expected non-nil config")
	}
	if engine.config.DefaultMethod != MethodPsExec {
		t.Errorf("Expected default method PsExec, got %s", engine.config.DefaultMethod)
	}
}

func TestLateralEngineExecutePsExec(t *testing.T) {
	engine := NewLateralEngine(nil)

	target := &Target{
		Host:      "192.168.1.100",
		IP:        "192.168.1.100",
		Port:      445,
		Protocol:  ProtoSMB,
		OS:        "windows",
		Reachable: true,
	}

	creds := &Credentials{
		Username: "admin",
		Password: "password123",
		Domain:   "CORP",
		AuthType: AuthPassword,
	}

	result, err := engine.Execute("psexec", target, creds)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
	if result.Method != MethodPsExec {
		t.Errorf("Expected method PsExec, got %s", result.Method)
	}
}

func TestLateralEngineExecuteWmiExec(t *testing.T) {
	engine := NewLateralEngine(nil)

	target := &Target{
		Host:      "192.168.1.100",
		IP:        "192.168.1.100",
		Port:      445,
		Protocol:  ProtoWMI,
		OS:        "windows",
		Reachable: true,
	}

	creds := &Credentials{
		Username: "admin",
		Password: "password123",
		Domain:   "CORP",
		AuthType: AuthPassword,
	}

	result, err := engine.Execute("wmiexec", target, creds)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
	if result.Method != MethodWmiExec {
		t.Errorf("Expected method WmiExec, got %s", result.Method)
	}
}

func TestLateralEngineExecuteWinRM(t *testing.T) {
	engine := NewLateralEngine(nil)

	target := &Target{
		Host:      "192.168.1.100",
		IP:        "192.168.1.100",
		Port:      5985,
		Protocol:  ProtoWinRM,
		OS:        "windows",
		Reachable: true,
	}

	creds := &Credentials{
		Username: "admin",
		Password: "password123",
		Domain:   "CORP",
		AuthType: AuthPassword,
	}

	result, err := engine.Execute("winrm", target, creds)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
	if result.Method != MethodWinRM {
		t.Errorf("Expected method WinRM, got %s", result.Method)
	}
}

func TestLateralEngineExecuteSSH(t *testing.T) {
	engine := NewLateralEngine(nil)

	target := &Target{
		Host:      "192.168.1.100",
		IP:        "192.168.1.100",
		Port:      22,
		Protocol:  ProtoSSH,
		OS:        "linux",
		Reachable: true,
	}

	creds := &Credentials{
		Username: "root",
		Password: "password123",
		AuthType: AuthPassword,
	}

	result, err := engine.Execute("ssh", target, creds)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
	if result.Method != MethodSSH {
		t.Errorf("Expected method SSH, got %s", result.Method)
	}
}

func TestLateralEngineExecuteUnsupportedMethod(t *testing.T) {
	engine := NewLateralEngine(nil)

	target := &Target{
		Host: "192.168.1.100",
	}

	creds := &Credentials{
		Username: "admin",
	}

	_, err := engine.Execute("unsupported", target, creds)
	if err == nil {
		t.Error("Expected error for unsupported method")
	}
}

func TestLateralEngineExecuteWithFallback(t *testing.T) {
	engine := NewLateralEngine(nil)

	target := &Target{
		Host:      "192.168.1.100",
		IP:        "192.168.1.100",
		Port:      445,
		Protocol:  ProtoSMB,
		OS:        "windows",
		Reachable: true,
	}

	creds := &Credentials{
		Username: "admin",
		Password: "password123",
		Domain:   "CORP",
		AuthType: AuthPassword,
	}

	result, err := engine.ExecuteWithFallback(target, creds)
	if err != nil {
		t.Fatalf("ExecuteWithFallback failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
}

func TestLateralEngineGetAvailableMethods(t *testing.T) {
	engine := NewLateralEngine(nil)

	methods := engine.GetAvailableMethods()
	if len(methods) == 0 {
		t.Error("Expected at least one method")
	}

	methodMap := make(map[LateralMethod]bool)
	for _, m := range methods {
		methodMap[m] = true
	}

	expectedMethods := []LateralMethod{
		MethodPsExec,
		MethodSMBExec,
		MethodAtExec,
		MethodWmiExec,
		MethodDCOMExec,
		MethodServiceExec,
		MethodNamedPipe,
		MethodPassTheHash,
		MethodWinRM,
		MethodRDP,
		MethodSSH,
		MethodPSRemoting,
	}

	for _, m := range expectedMethods {
		if !methodMap[m] {
			t.Errorf("Expected method %s not found", m)
		}
	}
}

func TestPsExecMethod(t *testing.T) {
	method := NewPsExecMethod()

	if method.Name() != "psexec" {
		t.Errorf("Expected name psexec, got %s", method.Name())
	}

	target := &Target{
		Host:      "192.168.1.100",
		Reachable: true,
	}

	creds := &Credentials{
		Username: "admin",
		Password: "password",
		AuthType: AuthPassword,
	}

	if !method.CanExecute(target, creds) {
		t.Error("Expected CanExecute to return true")
	}

	if !method.RequiresElevation() {
		t.Error("Expected RequiresElevation to return true")
	}

	result, err := method.Execute(target, creds)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
}

func TestSMBExecMethod(t *testing.T) {
	method := NewSMBExecMethod()

	if method.Name() != "smbexec" {
		t.Errorf("Expected name smbexec, got %s", method.Name())
	}

	target := &Target{
		Host:      "192.168.1.100",
		Reachable: true,
	}

	creds := &Credentials{
		Username: "admin",
		Password: "password",
		AuthType: AuthPassword,
	}

	if !method.CanExecute(target, creds) {
		t.Error("Expected CanExecute to return true")
	}

	result, err := method.Execute(target, creds)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
}

func TestWmiExecMethod(t *testing.T) {
	method := NewWmiExecMethod()

	if method.Name() != "wmiexec" {
		t.Errorf("Expected name wmiexec, got %s", method.Name())
	}

	target := &Target{
		Host:      "192.168.1.100",
		Reachable: true,
	}

	creds := &Credentials{
		Username: "admin",
		Hash:     "aad3b435b51404eeaad3b435b51404ee",
		AuthType: AuthHash,
	}

	if !method.CanExecute(target, creds) {
		t.Error("Expected CanExecute to return true")
	}

	result, err := method.Execute(target, creds)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
}

func TestPassTheHashMethod(t *testing.T) {
	method := NewPassTheHashMethod()

	if method.Name() != "pth" {
		t.Errorf("Expected name pth, got %s", method.Name())
	}

	target := &Target{
		Host:      "192.168.1.100",
		Reachable: true,
	}

	creds := &Credentials{
		Username: "admin",
		Hash:     "aad3b435b51404eeaad3b435b51404ee",
		AuthType: AuthHash,
	}

	if !method.CanExecute(target, creds) {
		t.Error("Expected CanExecute to return true")
	}

	result, err := method.Execute(target, creds)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
}

func TestPassTheHashEmptyHash(t *testing.T) {
	method := NewPassTheHashMethod()

	target := &Target{
		Host:      "192.168.1.100",
		Reachable: true,
	}

	creds := &Credentials{
		Username: "admin",
		Hash:     "",
		AuthType: AuthHash,
	}

	if method.CanExecute(target, creds) {
		t.Error("Expected CanExecute to return false for empty hash")
	}

	_, err := method.Execute(target, creds)
	if err == nil {
		t.Error("Expected error for empty hash")
	}
}

func TestWinRMMethod(t *testing.T) {
	method := NewWinRMMethod()

	if method.Name() != "winrm" {
		t.Errorf("Expected name winrm, got %s", method.Name())
	}

	target := &Target{
		Host:      "192.168.1.100",
		Port:      5985,
		Reachable: true,
	}

	creds := &Credentials{
		Username: "admin",
		Password: "password",
		AuthType: AuthPassword,
	}

	if !method.CanExecute(target, creds) {
		t.Error("Expected CanExecute to return true")
	}

	result, err := method.Execute(target, creds)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
}

func TestRDPMethod(t *testing.T) {
	method := NewRDPMethod()

	if method.Name() != "rdp" {
		t.Errorf("Expected name rdp, got %s", method.Name())
	}

	target := &Target{
		Host:      "192.168.1.100",
		Port:      3389,
		Reachable: true,
	}

	creds := &Credentials{
		Username: "admin",
		Password: "password",
		AuthType: AuthPassword,
	}

	if !method.CanExecute(target, creds) {
		t.Error("Expected CanExecute to return true")
	}

	result, err := method.Execute(target, creds)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
}

func TestSSHMethod(t *testing.T) {
	method := NewSSHMethod()

	if method.Name() != "ssh" {
		t.Errorf("Expected name ssh, got %s", method.Name())
	}

	target := &Target{
		Host:      "192.168.1.100",
		Port:      22,
		Reachable: true,
	}

	creds := &Credentials{
		Username: "root",
		Password: "password",
		AuthType: AuthPassword,
	}

	if !method.CanExecute(target, creds) {
		t.Error("Expected CanExecute to return true")
	}

	result, err := method.Execute(target, creds)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
}

func TestWinRMExec(t *testing.T) {
	target := &Target{
		Host: "192.168.1.100",
	}

	creds := &Credentials{
		Username: "admin",
		Password: "password",
	}

	exec := NewWinRMExec(target, creds)

	output, err := exec.ExecuteCommand("whoami")
	if err != nil {
		t.Fatalf("ExecuteCommand failed: %v", err)
	}
	if output == "" {
		t.Error("Expected non-empty output")
	}

	output, err = exec.ExecutePSCommand("Get-Process")
	if err != nil {
		t.Fatalf("ExecutePSCommand failed: %v", err)
	}
	if output == "" {
		t.Error("Expected non-empty output")
	}
}

func TestWinRMShell(t *testing.T) {
	target := &Target{
		Host: "192.168.1.100",
	}

	creds := &Credentials{
		Username: "admin",
		Password: "password",
	}

	shell := NewWinRMShell(target, creds)

	if !shell.IsActive() {
		t.Error("Expected shell to be active")
	}

	prompt, err := shell.Read()
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if prompt == "" {
		t.Error("Expected non-empty prompt")
	}

	output, err := shell.Write("dir")
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if output == "" {
		t.Error("Expected non-empty output")
	}

	shell.Close()
	if shell.IsActive() {
		t.Error("Expected shell to be closed")
	}
}

func TestSSHExec(t *testing.T) {
	target := &Target{
		Host: "192.168.1.100",
	}

	creds := &Credentials{
		Username: "root",
		Password: "password",
	}

	exec := NewSSHExec(target, creds)

	output, err := exec.ExecuteCommand("whoami")
	if err != nil {
		t.Fatalf("ExecuteCommand failed: %v", err)
	}
	if output == "" {
		t.Error("Expected non-empty output")
	}

	shell, err := exec.ExecuteShell()
	if err != nil {
		t.Fatalf("ExecuteShell failed: %v", err)
	}
	if shell == nil {
		t.Fatal("Expected non-nil shell")
	}
}

func TestSSHShell(t *testing.T) {
	target := &Target{
		Host: "192.168.1.100",
	}

	creds := &Credentials{
		Username: "root",
		Password: "password",
	}

	shell := NewSSHShell(target, creds)

	if !shell.IsActive() {
		t.Error("Expected shell to be active")
	}

	prompt, err := shell.Read()
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if prompt == "" {
		t.Error("Expected non-empty prompt")
	}

	output, err := shell.Write("ls -la")
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if output == "" {
		t.Error("Expected non-empty output")
	}

	shell.Close()
	if shell.IsActive() {
		t.Error("Expected shell to be closed")
	}
}

func TestRDPConnection(t *testing.T) {
	target := &Target{
		Host: "192.168.1.100",
	}

	creds := &Credentials{
		Username: "admin",
		Password: "password",
	}

	conn := NewRDPConnection(target, creds)

	if conn.IsConnected() {
		t.Error("Expected not connected initially")
	}

	err := conn.Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if !conn.IsConnected() {
		t.Error("Expected connected")
	}

	conn.Disconnect()
	if conn.IsConnected() {
		t.Error("Expected disconnected")
	}
}

func TestRDPTunnel(t *testing.T) {
	target := &Target{
		Host: "192.168.1.100",
	}

	creds := &Credentials{
		Username: "admin",
		Password: "password",
	}

	tunnel := NewRDPTunnel("127.0.0.1", 13389, target, creds)

	if tunnel.IsActive() {
		t.Error("Expected not active initially")
	}

	err := tunnel.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !tunnel.IsActive() {
		t.Error("Expected active")
	}

	tunnel.Stop()
	if tunnel.IsActive() {
		t.Error("Expected stopped")
	}
}

func TestSOCKS5Proxy(t *testing.T) {
	config := &SOCKS5Proxy{
		ListenAddr: "127.0.0.1",
		ListenPort: 1080,
		Target:     "192.168.1.100",
		TargetPort: 445,
	}

	proxy := NewSOCKS5ProxyMethod(config)

	if proxy.IsActive() {
		t.Error("Expected not active initially")
	}

	err := proxy.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !proxy.IsActive() {
		t.Error("Expected active")
	}

	addr := proxy.GetListenAddr()
	if addr != "127.0.0.1:1080" {
		t.Errorf("Expected 127.0.0.1:1080, got %s", addr)
	}

	proxy.Stop()
	if proxy.IsActive() {
		t.Error("Expected stopped")
	}
}

func TestPortForward(t *testing.T) {
	config := &PortForward{
		ListenAddr: "127.0.0.1",
		ListenPort: 8080,
		TargetAddr: "192.168.1.100",
		TargetPort: 80,
	}

	forward := NewPortForwardMethod(config)

	if forward.IsActive() {
		t.Error("Expected not active initially")
	}

	err := forward.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !forward.IsActive() {
		t.Error("Expected active")
	}

	localAddr := forward.GetListenAddr()
	if localAddr != "127.0.0.1:8080" {
		t.Errorf("Expected 127.0.0.1:8080, got %s", localAddr)
	}

	targetAddr := forward.GetTargetAddr()
	if targetAddr != "192.168.1.100:80" {
		t.Errorf("Expected 192.168.1.100:80, got %s", targetAddr)
	}

	forward.Stop()
	if forward.IsActive() {
		t.Error("Expected stopped")
	}
}

func TestTCPTunnel(t *testing.T) {
	config := &TCPTunnel{
		ListenAddr: "127.0.0.1",
		ListenPort: 9090,
		RemoteAddr: "192.168.1.100",
		RemotePort: 445,
		Encrypted:  true,
	}

	tunnel := NewTCPTunnelMethod(config)

	if tunnel.IsActive() {
		t.Error("Expected not active initially")
	}

	err := tunnel.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !tunnel.IsActive() {
		t.Error("Expected active")
	}

	tunnel.Stop()
	if tunnel.IsActive() {
		t.Error("Expected stopped")
	}
}

func TestPivotManager(t *testing.T) {
	pm := NewPivotManager()

	if len(pm.ListPivots()) != 0 {
		t.Error("Expected empty pivot list")
	}

	config1 := &SOCKS5Proxy{
		ListenAddr: "127.0.0.1",
		ListenPort: 1080,
	}
	proxy1 := NewSOCKS5ProxyMethod(config1)
	pm.AddPivot("proxy1", proxy1)

	config2 := &PortForward{
		ListenAddr: "127.0.0.1",
		ListenPort: 8080,
	}
	forward1 := NewPortForwardMethod(config2)
	pm.AddPivot("forward1", forward1)

	if len(pm.ListPivots()) != 2 {
		t.Errorf("Expected 2 pivots, got %d", len(pm.ListPivots()))
	}

	pivot, ok := pm.GetPivot("proxy1")
	if !ok || pivot == nil {
		t.Error("Expected to find proxy1")
	}

	pm.RemovePivot("proxy1")
	if len(pm.ListPivots()) != 1 {
		t.Errorf("Expected 1 pivot after removal, got %d", len(pm.ListPivots()))
	}

	pm.StopAll()
	if len(pm.ListPivots()) != 0 {
		t.Error("Expected empty pivot list after stop all")
	}
}

func TestTargetMetadata(t *testing.T) {
	target := &Target{
		Host:     "192.168.1.100",
		Hostname: "web01",
		OS:       "windows",
		Domain:   "CORP",
		Metadata: map[string]string{
			"version": "10.0.17763",
			"role":    "member",
		},
	}

	if target.Host != "192.168.1.100" {
		t.Errorf("Expected host 192.168.1.100, got %s", target.Host)
	}
	if target.Hostname != "web01" {
		t.Errorf("Expected hostname web01, got %s", target.Hostname)
	}
	if target.Metadata["version"] != "10.0.17763" {
		t.Errorf("Expected version 10.0.17763, got %s", target.Metadata["version"])
	}
}

func TestCredentialsTypes(t *testing.T) {
	tests := []struct {
		name     string
		creds    *Credentials
		wantErr  bool
	}{
		{
			name: "password auth",
			creds: &Credentials{
				Username: "admin",
				Password: "password",
				AuthType: AuthPassword,
			},
			wantErr: false,
		},
		{
			name: "hash auth",
			creds: &Credentials{
				Username: "admin",
				Hash:     "aad3b435b51404eeaad3b435b51404ee",
				AuthType: AuthHash,
			},
			wantErr: false,
		},
		{
			name: "ticket auth",
			creds: &Credentials{
				Username: "admin",
				Ticket:   []byte("ticket-data"),
				AuthType: AuthTicket,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.creds.Username == "" {
				t.Error("Expected non-empty username")
			}
		})
	}
}

func TestLateralConfigDefaults(t *testing.T) {
	config := DefaultLateralConfig()

	if config.DefaultMethod != MethodPsExec {
		t.Errorf("Expected default method PsExec, got %s", config.DefaultMethod)
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", config.Timeout)
	}
	if config.MaxRetries != 3 {
		t.Errorf("Expected max retries 3, got %d", config.MaxRetries)
	}
	if config.SMBPort != 445 {
		t.Errorf("Expected SMB port 445, got %d", config.SMBPort)
	}
	if config.WinRMPort != 5985 {
		t.Errorf("Expected WinRM port 5985, got %d", config.WinRMPort)
	}
	if config.RDPPort != 3389 {
		t.Errorf("Expected RDP port 3389, got %d", config.RDPPort)
	}
	if config.SSHPort != 22 {
		t.Errorf("Expected SSH port 22, got %d", config.SSHPort)
	}
}
