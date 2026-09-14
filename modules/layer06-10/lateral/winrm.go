package lateral

import (
	"fmt"
	"time"
)

type WinRMMethod struct{}

func NewWinRMMethod() *WinRMMethod {
	return &WinRMMethod{}
}

func (m *WinRMMethod) Name() string {
	return "winrm"
}

func (m *WinRMMethod) Execute(target *Target, creds *Credentials) (*LateralResult, error) {
	if target == nil || creds == nil {
		return nil, fmt.Errorf("target and credentials are required")
	}

	if creds.Username == "" || creds.Password == "" {
		return nil, fmt.Errorf("username and password are required for WinRM")
	}

	result := &LateralResult{
		Success:   true,
		Method:    MethodWinRM,
		Target:    target,
		Output:    fmt.Sprintf("WinRM execution on %s", target.Host),
		Protocol:  ProtoWinRM,
		SessionID: fmt.Sprintf("winrm-%s-%d", target.Host, time.Now().UnixNano()),
	}

	return result, nil
}

func (m *WinRMMethod) CanExecute(target *Target, creds *Credentials) bool {
	if target == nil || creds == nil {
		return false
	}
	if creds.AuthType != AuthPassword {
		return false
	}
	return target.Reachable && (target.Port == 5985 || target.Port == 5986 || target.Port == 0)
}

func (m *WinRMMethod) RequiresElevation() bool {
	return false
}

type WinRMExec struct {
	target *Target
	creds  *Credentials
}

func NewWinRMExec(target *Target, creds *Credentials) *WinRMExec {
	return &WinRMExec{
		target: target,
		creds:  creds,
	}
}

func (e *WinRMExec) ExecuteCommand(command string) (string, error) {
	if e.target == nil || e.creds == nil {
		return "", fmt.Errorf("target and credentials are required")
	}

	if command == "" {
		return "", fmt.Errorf("command is required")
	}

	output := fmt.Sprintf("[WinRM] Executing on %s: %s", e.target.Host, command)
	return output, nil
}

func (e *WinRMExec) ExecutePSCommand(command string) (string, error) {
	if e.target == nil || e.creds == nil {
		return "", fmt.Errorf("target and credentials are required")
	}

	output := fmt.Sprintf("[WinRM/PS] Executing on %s: %s", e.target.Host, command)
	return output, nil
}

type WinRMShell struct {
	target   *Target
	creds    *Credentials
	session  string
	active   bool
}

func NewWinRMShell(target *Target, creds *Credentials) *WinRMShell {
	return &WinRMShell{
		target:  target,
		creds:   creds,
		session: fmt.Sprintf("winrm-shell-%s-%d", target.Host, time.Now().UnixNano()),
		active:  true,
	}
}

func (s *WinRMShell) Read() (string, error) {
	if !s.active {
		return "", fmt.Errorf("shell is closed")
	}
	return fmt.Sprintf("[WinRM:%s]> ", s.target.Host), nil
}

func (s *WinRMShell) Write(command string) (string, error) {
	if !s.active {
		return "", fmt.Errorf("shell is closed")
	}

	output := fmt.Sprintf("[WinRM:%s] %s", s.target.Host, command)
	return output, nil
}

func (s *WinRMShell) Close() {
	s.active = false
}

func (s *WinRMShell) IsActive() bool {
	return s.active
}

func (s *WinRMShell) GetSessionID() string {
	return s.session
}

type PSRemotingMethod struct{}

func NewPSRemotingMethod() *PSRemotingMethod {
	return &PSRemotingMethod{}
}

func (m *PSRemotingMethod) Name() string {
	return "psremoting"
}

func (m *PSRemotingMethod) Execute(target *Target, creds *Credentials) (*LateralResult, error) {
	if target == nil || creds == nil {
		return nil, fmt.Errorf("target and credentials are required")
	}

	result := &LateralResult{
		Success:   true,
		Method:    MethodPSRemoting,
		Target:    target,
		Output:    fmt.Sprintf("PS Remoting execution on %s", target.Host),
		Protocol:  ProtoWinRM,
		SessionID: fmt.Sprintf("psremoting-%s-%d", target.Host, time.Now().UnixNano()),
	}

	return result, nil
}

func (m *PSRemotingMethod) CanExecute(target *Target, creds *Credentials) bool {
	if target == nil || creds == nil {
		return false
	}
	if creds.AuthType != AuthPassword {
		return false
	}
	return target.Reachable
}

func (m *PSRemotingMethod) RequiresElevation() bool {
	return false
}
