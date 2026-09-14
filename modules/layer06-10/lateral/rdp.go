package lateral

import (
	"fmt"
	"time"
)

type RDPMethod struct{}

func NewRDPMethod() *RDPMethod {
	return &RDPMethod{}
}

func (m *RDPMethod) Name() string {
	return "rdp"
}

func (m *RDPMethod) Execute(target *Target, creds *Credentials) (*LateralResult, error) {
	if target == nil || creds == nil {
		return nil, fmt.Errorf("target and credentials are required")
	}

	if creds.Username == "" || creds.Password == "" {
		return nil, fmt.Errorf("username and password are required for RDP")
	}

	result := &LateralResult{
		Success:   true,
		Method:    MethodRDP,
		Target:    target,
		Output:    fmt.Sprintf("RDP connection to %s", target.Host),
		Protocol:  ProtoRDP,
		SessionID: fmt.Sprintf("rdp-%s-%d", target.Host, time.Now().UnixNano()),
	}

	return result, nil
}

func (m *RDPMethod) CanExecute(target *Target, creds *Credentials) bool {
	if target == nil || creds == nil {
		return false
	}
	if creds.AuthType != AuthPassword {
		return false
	}
	return target.Reachable && (target.Port == 3389 || target.Port == 0)
}

func (m *RDPMethod) RequiresElevation() bool {
	return false
}

type RDPConnection struct {
	target    *Target
	creds     *Credentials
	sessionID string
	connected bool
}

func NewRDPConnection(target *Target, creds *Credentials) *RDPConnection {
	return &RDPConnection{
		target:    target,
		creds:     creds,
		sessionID: fmt.Sprintf("rdp-conn-%s-%d", target.Host, time.Now().UnixNano()),
	}
}

func (c *RDPConnection) Connect() error {
	if c.target == nil || c.creds == nil {
		return fmt.Errorf("target and credentials are required")
	}

	c.connected = true
	return nil
}

func (c *RDPConnection) Disconnect() {
	c.connected = false
}

func (c *RDPConnection) IsConnected() bool {
	return c.connected
}

func (c *RDPConnection) GetSessionID() string {
	return c.sessionID
}

type RDPTunnel struct {
	listenAddr string
	listenPort int
	target     *Target
	creds      *Credentials
	active     bool
}

func NewRDPTunnel(listenAddr string, listenPort int, target *Target, creds *Credentials) *RDPTunnel {
	return &RDPTunnel{
		listenAddr: listenAddr,
		listenPort: listenPort,
		target:     target,
		creds:      creds,
		active:     false,
	}
}

func (t *RDPTunnel) Start() error {
	if t.target == nil {
		return fmt.Errorf("target is required")
	}

	t.active = true
	return nil
}

func (t *RDPTunnel) Stop() {
	t.active = false
}

func (t *RDPTunnel) IsActive() bool {
	return t.active
}

func (t *RDPTunnel) GetListenAddr() string {
	return fmt.Sprintf("%s:%d", t.listenAddr, t.listenPort)
}

type RDPSessionHijack struct {
	target      *Target
	sessionID   int
	processName string
	active      bool
}

func NewRDPSessionHijack(target *Target, sessionID int) *RDPSessionHijack {
	return &RDPSessionHijack{
		target:      target,
		sessionID:   sessionID,
		processName: "explorer.exe",
	}
}

func (h *RDPSessionHijack) Hijack() error {
	if h.target == nil {
		return fmt.Errorf("target is required")
	}

	h.active = true
	return nil
}

func (h *RDPSessionHijack) Release() {
	h.active = false
}

func (h *RDPSessionHijack) IsActive() bool {
	return h.active
}

func (h *RDPSessionHijack) GetSessionID() int {
	return h.sessionID
}
