package lateral

import (
	"fmt"
	"time"
)

type SSHMethod struct{}

func NewSSHMethod() *SSHMethod {
	return &SSHMethod{}
}

func (m *SSHMethod) Name() string {
	return "ssh"
}

func (m *SSHMethod) Execute(target *Target, creds *Credentials) (*LateralResult, error) {
	if target == nil || creds == nil {
		return nil, fmt.Errorf("target and credentials are required")
	}

	if creds.Username == "" {
		return nil, fmt.Errorf("username is required for SSH")
	}

	result := &LateralResult{
		Success:   true,
		Method:    MethodSSH,
		Target:    target,
		Output:    fmt.Sprintf("SSH connection to %s", target.Host),
		Protocol:  ProtoSSH,
		SessionID: fmt.Sprintf("ssh-%s-%d", target.Host, time.Now().UnixNano()),
	}

	return result, nil
}

func (m *SSHMethod) CanExecute(target *Target, creds *Credentials) bool {
	if target == nil || creds == nil {
		return false
	}
	if creds.AuthType != AuthPassword && creds.AuthType != AuthKey {
		return false
	}
	return target.Reachable && (target.Port == 22 || target.Port == 0)
}

func (m *SSHMethod) RequiresElevation() bool {
	return false
}

type SSHExec struct {
	target  *Target
	creds   *Credentials
	session string
}

func NewSSHExec(target *Target, creds *Credentials) *SSHExec {
	return &SSHExec{
		target:  target,
		creds:   creds,
		session: fmt.Sprintf("ssh-%s-%d", target.Host, time.Now().UnixNano()),
	}
}

func (e *SSHExec) ExecuteCommand(command string) (string, error) {
	if e.target == nil || e.creds == nil {
		return "", fmt.Errorf("target and credentials are required")
	}

	if command == "" {
		return "", fmt.Errorf("command is required")
	}

	output := fmt.Sprintf("[SSH] Executing on %s: %s", e.target.Host, command)
	return output, nil
}

func (e *SSHExec) ExecuteShell() (*SSHShell, error) {
	if e.target == nil || e.creds == nil {
		return nil, fmt.Errorf("target and credentials are required")
	}

	return NewSSHShell(e.target, e.creds), nil
}

type SSHShell struct {
	target   *Target
	creds    *Credentials
	session  string
	active   bool
}

func NewSSHShell(target *Target, creds *Credentials) *SSHShell {
	return &SSHShell{
		target:  target,
		creds:   creds,
		session: fmt.Sprintf("ssh-shell-%s-%d", target.Host, time.Now().UnixNano()),
		active:  true,
	}
}

func (s *SSHShell) Read() (string, error) {
	if !s.active {
		return "", fmt.Errorf("shell is closed")
	}
	return fmt.Sprintf("[%s@%s]$ ", s.creds.Username, s.target.Host), nil
}

func (s *SSHShell) Write(command string) (string, error) {
	if !s.active {
		return "", fmt.Errorf("shell is closed")
	}

	output := fmt.Sprintf("[%s@%s] %s", s.creds.Username, s.target.Host, command)
	return output, nil
}

func (s *SSHShell) Close() {
	s.active = false
}

func (s *SSHShell) IsActive() bool {
	return s.active
}

func (s *SSHShell) GetSessionID() string {
	return s.session
}

type SSHTunnel struct {
	localAddr  string
	localPort  int
	remoteAddr string
	remotePort int
	target     *Target
	creds      *Credentials
	active     bool
}

func NewSSHTunnel(localAddr string, localPort int, remoteAddr string, remotePort int, target *Target, creds *Credentials) *SSHTunnel {
	return &SSHTunnel{
		localAddr:  localAddr,
		localPort:  localPort,
		remoteAddr: remoteAddr,
		remotePort: remotePort,
		target:     target,
		creds:      creds,
		active:     false,
	}
}

func (t *SSHTunnel) Start() error {
	if t.target == nil {
		return fmt.Errorf("target is required")
	}

	t.active = true
	return nil
}

func (t *SSHTunnel) Stop() {
	t.active = false
}

func (t *SSHTunnel) IsActive() bool {
	return t.active
}

func (t *SSHTunnel) GetLocalAddr() string {
	return fmt.Sprintf("%s:%d", t.localAddr, t.localPort)
}

func (t *SSHTunnel) GetRemoteAddr() string {
	return fmt.Sprintf("%s:%d", t.remoteAddr, t.remotePort)
}
