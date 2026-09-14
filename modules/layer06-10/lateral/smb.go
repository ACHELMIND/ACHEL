package lateral

import (
	"fmt"
	"time"
)

type PsExecMethod struct{}

func NewPsExecMethod() *PsExecMethod {
	return &PsExecMethod{}
}

func (m *PsExecMethod) Name() string {
	return "psexec"
}

func (m *PsExecMethod) Execute(target *Target, creds *Credentials) (*LateralResult, error) {
	if target == nil || creds == nil {
		return nil, fmt.Errorf("target and credentials are required")
	}

	result := &LateralResult{
		Success:   true,
		Method:    MethodPsExec,
		Target:    target,
		Output:    fmt.Sprintf("PsExec execution on %s", target.Host),
		Protocol:  ProtoSMB,
		SessionID: fmt.Sprintf("psexec-%s-%d", target.Host, time.Now().UnixNano()),
	}

	return result, nil
}

func (m *PsExecMethod) CanExecute(target *Target, creds *Credentials) bool {
	if target == nil || creds == nil {
		return false
	}
	if creds.AuthType == AuthPassword || creds.AuthType == AuthHash {
		return target.Reachable
	}
	return false
}

func (m *PsExecMethod) RequiresElevation() bool {
	return true
}

type SMBExecMethod struct{}

func NewSMBExecMethod() *SMBExecMethod {
	return &SMBExecMethod{}
}

func (m *SMBExecMethod) Name() string {
	return "smbexec"
}

func (m *SMBExecMethod) Execute(target *Target, creds *Credentials) (*LateralResult, error) {
	if target == nil || creds == nil {
		return nil, fmt.Errorf("target and credentials are required")
	}

	result := &LateralResult{
		Success:   true,
		Method:    MethodSMBExec,
		Target:    target,
		Output:    fmt.Sprintf("SMBExec execution on %s", target.Host),
		Protocol:  ProtoSMB,
		SessionID: fmt.Sprintf("smbexec-%s-%d", target.Host, time.Now().UnixNano()),
	}

	return result, nil
}

func (m *SMBExecMethod) CanExecute(target *Target, creds *Credentials) bool {
	if target == nil || creds == nil {
		return false
	}
	return target.Reachable && (creds.AuthType == AuthPassword || creds.AuthType == AuthHash)
}

func (m *SMBExecMethod) RequiresElevation() bool {
	return true
}

type AtExecMethod struct{}

func NewAtExecMethod() *AtExecMethod {
	return &AtExecMethod{}
}

func (m *AtExecMethod) Name() string {
	return "atexec"
}

func (m *AtExecMethod) Execute(target *Target, creds *Credentials) (*LateralResult, error) {
	if target == nil || creds == nil {
		return nil, fmt.Errorf("target and credentials are required")
	}

	result := &LateralResult{
		Success:   true,
		Method:    MethodAtExec,
		Target:    target,
		Output:    fmt.Sprintf("AtExec execution on %s", target.Host),
		Protocol:  ProtoSMB,
		SessionID: fmt.Sprintf("atexec-%s-%d", target.Host, time.Now().UnixNano()),
	}

	return result, nil
}

func (m *AtExecMethod) CanExecute(target *Target, creds *Credentials) bool {
	if target == nil || creds == nil {
		return false
	}
	return target.Reachable && creds.AuthType == AuthPassword
}

func (m *AtExecMethod) RequiresElevation() bool {
	return true
}

type WmiExecMethod struct{}

func NewWmiExecMethod() *WmiExecMethod {
	return &WmiExecMethod{}
}

func (m *WmiExecMethod) Name() string {
	return "wmiexec"
}

func (m *WmiExecMethod) Execute(target *Target, creds *Credentials) (*LateralResult, error) {
	if target == nil || creds == nil {
		return nil, fmt.Errorf("target and credentials are required")
	}

	result := &LateralResult{
		Success:   true,
		Method:    MethodWmiExec,
		Target:    target,
		Output:    fmt.Sprintf("WMIExec execution on %s", target.Host),
		Protocol:  ProtoWMI,
		SessionID: fmt.Sprintf("wmiexec-%s-%d", target.Host, time.Now().UnixNano()),
	}

	return result, nil
}

func (m *WmiExecMethod) CanExecute(target *Target, creds *Credentials) bool {
	if target == nil || creds == nil {
		return false
	}
	return target.Reachable && (creds.AuthType == AuthPassword || creds.AuthType == AuthHash)
}

func (m *WmiExecMethod) RequiresElevation() bool {
	return false
}

type DCOMExecMethod struct{}

func NewDCOMExecMethod() *DCOMExecMethod {
	return &DCOMExecMethod{}
}

func (m *DCOMExecMethod) Name() string {
	return "dcomexec"
}

func (m *DCOMExecMethod) Execute(target *Target, creds *Credentials) (*LateralResult, error) {
	if target == nil || creds == nil {
		return nil, fmt.Errorf("target and credentials are required")
	}

	result := &LateralResult{
		Success:   true,
		Method:    MethodDCOMExec,
		Target:    target,
		Output:    fmt.Sprintf("DCOMExec execution on %s", target.Host),
		Protocol:  ProtoDCOM,
		SessionID: fmt.Sprintf("dcomexec-%s-%d", target.Host, time.Now().UnixNano()),
	}

	return result, nil
}

func (m *DCOMExecMethod) CanExecute(target *Target, creds *Credentials) bool {
	if target == nil || creds == nil {
		return false
	}
	return target.Reachable && creds.AuthType == AuthPassword
}

func (m *DCOMExecMethod) RequiresElevation() bool {
	return false
}

type ServiceExecMethod struct{}

func NewServiceExecMethod() *ServiceExecMethod {
	return &ServiceExecMethod{}
}

func (m *ServiceExecMethod) Name() string {
	return "serviceexec"
}

func (m *ServiceExecMethod) Execute(target *Target, creds *Credentials) (*LateralResult, error) {
	if target == nil || creds == nil {
		return nil, fmt.Errorf("target and credentials are required")
	}

	result := &LateralResult{
		Success:   true,
		Method:    MethodServiceExec,
		Target:    target,
		Output:    fmt.Sprintf("ServiceExec execution on %s", target.Host),
		Protocol:  ProtoSMB,
		SessionID: fmt.Sprintf("svcexec-%s-%d", target.Host, time.Now().UnixNano()),
	}

	return result, nil
}

func (m *ServiceExecMethod) CanExecute(target *Target, creds *Credentials) bool {
	if target == nil || creds == nil {
		return false
	}
	return target.Reachable && creds.AuthType == AuthPassword
}

func (m *ServiceExecMethod) RequiresElevation() bool {
	return true
}

type NamedPipeMethod struct{}

func NewNamedPipeMethod() *NamedPipeMethod {
	return &NamedPipeMethod{}
}

func (m *NamedPipeMethod) Name() string {
	return "namedpipe"
}

func (m *NamedPipeMethod) Execute(target *Target, creds *Credentials) (*LateralResult, error) {
	if target == nil || creds == nil {
		return nil, fmt.Errorf("target and credentials are required")
	}

	result := &LateralResult{
		Success:   true,
		Method:    MethodNamedPipe,
		Target:    target,
		Output:    fmt.Sprintf("NamedPipe execution on %s", target.Host),
		Protocol:  ProtoSMB,
		SessionID: fmt.Sprintf("namedpipe-%s-%d", target.Host, time.Now().UnixNano()),
	}

	return result, nil
}

func (m *NamedPipeMethod) CanExecute(target *Target, creds *Credentials) bool {
	if target == nil || creds == nil {
		return false
	}
	return target.Reachable && creds.AuthType == AuthPassword
}

func (m *NamedPipeMethod) RequiresElevation() bool {
	return false
}

type PassTheHashMethod struct{}

func NewPassTheHashMethod() *PassTheHashMethod {
	return &PassTheHashMethod{}
}

func (m *PassTheHashMethod) Name() string {
	return "pth"
}

func (m *PassTheHashMethod) Execute(target *Target, creds *Credentials) (*LateralResult, error) {
	if target == nil || creds == nil {
		return nil, fmt.Errorf("target and credentials are required")
	}

	if creds.Hash == "" {
		return nil, fmt.Errorf("NTLM hash is required for pass-the-hash")
	}

	result := &LateralResult{
		Success:   true,
		Method:    MethodPassTheHash,
		Target:    target,
		Output:    fmt.Sprintf("Pass-the-Hash execution on %s", target.Host),
		Protocol:  ProtoSMB,
		SessionID: fmt.Sprintf("pth-%s-%d", target.Host, time.Now().UnixNano()),
	}

	return result, nil
}

func (m *PassTheHashMethod) CanExecute(target *Target, creds *Credentials) bool {
	if target == nil || creds == nil {
		return false
	}
	return target.Reachable && creds.AuthType == AuthHash && creds.Hash != ""
}

func (m *PassTheHashMethod) RequiresElevation() bool {
	return false
}
