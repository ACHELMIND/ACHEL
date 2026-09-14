package lateral

import (
	"fmt"
	"time"
)

type SOCKS5ProxyMethod struct {
	config *SOCKS5Proxy
}

func NewSOCKS5ProxyMethod(config *SOCKS5Proxy) *SOCKS5ProxyMethod {
	return &SOCKS5ProxyMethod{config: config}
}

func (m *SOCKS5ProxyMethod) Start() error {
	if m.config == nil {
		return fmt.Errorf("proxy config is required")
	}

	m.config.Active = true
	return nil
}

func (m *SOCKS5ProxyMethod) Stop() {
	if m.config != nil {
		m.config.Active = false
	}
}

func (m *SOCKS5ProxyMethod) IsActive() bool {
	return m.config != nil && m.config.Active
}

func (m *SOCKS5ProxyMethod) GetListenAddr() string {
	if m.config == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", m.config.ListenAddr, m.config.ListenPort)
}

type PortForwardMethod struct {
	config *PortForward
}

func NewPortForwardMethod(config *PortForward) *PortForwardMethod {
	return &PortForwardMethod{config: config}
}

func (m *PortForwardMethod) Start() error {
	if m.config == nil {
		return fmt.Errorf("port forward config is required")
	}

	m.config.Active = true
	return nil
}

func (m *PortForwardMethod) Stop() {
	if m.config != nil {
		m.config.Active = false
	}
}

func (m *PortForwardMethod) IsActive() bool {
	return m.config != nil && m.config.Active
}

func (m *PortForwardMethod) GetListenAddr() string {
	if m.config == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", m.config.ListenAddr, m.config.ListenPort)
}

func (m *PortForwardMethod) GetTargetAddr() string {
	if m.config == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", m.config.TargetAddr, m.config.TargetPort)
}

type TCPTunnelMethod struct {
	config *TCPTunnel
}

func NewTCPTunnelMethod(config *TCPTunnel) *TCPTunnelMethod {
	return &TCPTunnelMethod{config: config}
}

func (m *TCPTunnelMethod) Start() error {
	if m.config == nil {
		return fmt.Errorf("TCP tunnel config is required")
	}

	m.config.Active = true
	return nil
}

func (m *TCPTunnelMethod) Stop() {
	if m.config != nil {
		m.config.Active = false
	}
}

func (m *TCPTunnelMethod) IsActive() bool {
	return m.config != nil && m.config.Active
}

func (m *TCPTunnelMethod) GetListenAddr() string {
	if m.config == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", m.config.ListenAddr, m.config.ListenPort)
}

func (m *TCPTunnelMethod) GetRemoteAddr() string {
	if m.config == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", m.config.RemoteAddr, m.config.RemotePort)
}

type DNSTunnelMethod struct {
	config   *DNSTunnel
	stopChan chan struct{}
}

func NewDNSTunnelMethod(config *DNSTunnel) *DNSTunnelMethod {
	return &DNSTunnelMethod{
		config:   config,
		stopChan: make(chan struct{}),
	}
}

func (m *DNSTunnelMethod) Start() error {
	if m.config == nil {
		return fmt.Errorf("DNS tunnel config is required")
	}

	m.config.Active = true
	return nil
}

func (m *DNSTunnelMethod) Stop() {
	if m.config != nil {
		m.config.Active = false
	}
	close(m.stopChan)
}

func (m *DNSTunnelMethod) IsActive() bool {
	return m.config != nil && m.config.Active
}

func (m *DNSTunnelMethod) GetDomain() string {
	if m.config == nil {
		return ""
	}
	return m.config.Domain
}

type ICMPTunnelMethod struct {
	config   *ICMPTunnel
	stopChan chan struct{}
}

func NewICMPTunnelMethod(config *ICMPTunnel) *ICMPTunnelMethod {
	return &ICMPTunnelMethod{
		config:   config,
		stopChan: make(chan struct{}),
	}
}

func (m *ICMPTunnelMethod) Start() error {
	if m.config == nil {
		return fmt.Errorf("ICMP tunnel config is required")
	}

	m.config.Active = true
	return nil
}

func (m *ICMPTunnelMethod) Stop() {
	if m.config != nil {
		m.config.Active = false
	}
	close(m.stopChan)
}

func (m *ICMPTunnelMethod) IsActive() bool {
	return m.config != nil && m.config.Active
}

func (m *ICMPTunnelMethod) GetTarget() string {
	if m.config == nil {
		return ""
	}
	return m.config.TargetAddr
}

type PivotManager struct {
	pivots map[string]interface{}
	mu     map[string]chan struct{}
}

func NewPivotManager() *PivotManager {
	return &PivotManager{
		pivots: make(map[string]interface{}),
		mu:     make(map[string]chan struct{}),
	}
}

func (pm *PivotManager) AddPivot(name string, pivot interface{}) {
	pm.pivots[name] = pivot
	pm.mu[name] = make(chan struct{})
}

func (pm *PivotManager) RemovePivot(name string) {
	delete(pm.pivots, name)
	if ch, ok := pm.mu[name]; ok {
		close(ch)
		delete(pm.mu, name)
	}
}

func (pm *PivotManager) GetPivot(name string) (interface{}, bool) {
	pivot, ok := pm.pivots[name]
	return pivot, ok
}

func (pm *PivotManager) ListPivots() []string {
	names := make([]string, 0, len(pm.pivots))
	for name := range pm.pivots {
		names = append(names, name)
	}
	return names
}

func (pm *PivotManager) StopAll() {
	for name := range pm.pivots {
		pm.RemovePivot(name)
	}
}

type TunnelConfig struct {
	Type       string
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
	Target     *Target
	Creds      *Credentials
	Encrypted  bool
	Key        []byte
	KeepAlive  time.Duration
}

func DefaultTunnelConfig() *TunnelConfig {
	return &TunnelConfig{
		Type:      "tcp",
		LocalAddr: "127.0.0.1",
		LocalPort: 1080,
		Encrypted: false,
		KeepAlive: 30 * time.Second,
	}
}
