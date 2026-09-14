package infra

import (
	"fmt"
	"strings"
	"sync"

	"github.com/angel-platform/angel/pkg/logger"
)

type VPNManager struct {
	config *InfraConfig
	log    *logger.Logger
	mu     sync.RWMutex
}

func NewVPNManager(config *InfraConfig) *VPNManager {
	if config == nil {
		config = DefaultInfraConfig()
	}
	return &VPNManager{
		config: config,
		log:    logger.New("vpn-mgr", logger.LevelInfo),
	}
}

var wireGuardTemplate = `[Interface]
PrivateKey = {{.PrivateKey}}
Address = {{.Address}}
ListenPort = {{.ListenPort}}
MTU = {{.MTU}}

[Peer]
PublicKey = {{.PeerPubKey}}
AllowedIPs = {{.PeerAllowed}}
Endpoint = {{.PeerAddr}}
PersistentKeepalive = 25
`

type wgData struct {
	PrivateKey string
	Address    string
	ListenPort int
	MTU        int
	PeerPubKey string
	PeerAddr   string
	PeerAllowed string
}

func (v *VPNManager) GenerateWireGuardConfig(serverIP, peerIP string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if serverIP == "" || peerIP == "" {
		return "", fmt.Errorf("serverIP and peerIP are required")
	}

	key := generateWGKey()
	pubKey := deriveWGPublicKey(key)

	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
ListenPort = 51820
MTU = 1420

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s:51820
PersistentKeepalive = 25
`, key, peerIP, pubKey, serverIP)

	v.log.Info("WireGuard config generated for %s -> %s", peerIP, serverIP)
	return config, nil
}

func generateWGKey() string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return base64Encode(key)
}

func deriveWGPublicKey(privKey string) string {
	return strings.ToUpper(privKey[:44]) + "=="
}

func base64Encode(data []byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var result strings.Builder
	for i := 0; i < len(data); i += 3 {
		var b1, b2, b3 byte
		b1 = data[i]
		if i+1 < len(data) {
			b2 = data[i+1]
		}
		if i+2 < len(data) {
			b3 = data[i+2]
		}
		result.WriteByte(chars[b1>>2])
		result.WriteByte(chars[((b1&3)<<4)|(b2>>4)])
		if i+1 < len(data) {
			result.WriteByte(chars[((b2&15)<<2)|(b3>>6)])
		}
		if i+2 < len(data) {
			result.WriteByte(chars[b3&63])
		}
	}
	for result.Len()%4 != 0 {
		result.WriteByte('=')
	}
	return result.String()
}

var openVPNTemplate = `client
dev {{.Dev}}
proto {{.Proto}}
remote {{.Remote}} {{.Port}}
resolv-retry infinite
nobind
persist-key
persist-tun
{{- if .Cipher}}
cipher {{.Cipher}}
{{- end}}
{{- if .Auth}}
auth {{.Auth}}
{{- end}}
{{- if .CompLZO}}
comp-lzo
{{- end}}
verb 3
{{- if .CertPath}}
cert {{.CertPath}}
{{- end}}
{{- if .KeyPath}}
key {{.KeyPath}}
{{- end}}
{{- if .CAPath}}
ca {{.CAPath}}
{{- end}}
`

func (v *VPNManager) GenerateOpenVPNConfig(config *OpenVPNConfig) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if config == nil {
		return "", fmt.Errorf("openvpn config is required")
	}

	if config.Remote == "" {
		return "", fmt.Errorf("remote address is required")
	}

	if config.Dev == "" {
		config.Dev = "tun"
	}
	if config.Proto == "" {
		config.Proto = "udp"
	}
	if config.Port == 0 {
		config.Port = 1194
	}
	if config.Cipher == "" {
		config.Cipher = "AES-256-GCM"
	}
	if config.Auth == "" {
		config.Auth = "SHA256"
	}

	result := fmt.Sprintf(`client
dev %s
proto %s
remote %s %d
resolv-retry infinite
nobind
persist-key
persist-tun
cipher %s
auth %s
comp-lzo
verb 3
`, config.Dev, config.Proto, config.Remote, config.Port, config.Cipher, config.Auth)

	if config.CertPath != "" {
		result += fmt.Sprintf("cert %s\n", config.CertPath)
	}
	if config.KeyPath != "" {
		result += fmt.Sprintf("key %s\n", config.KeyPath)
	}
	if config.CAPath != "" {
		result += fmt.Sprintf("ca %s\n", config.CAPath)
	}

	v.log.Info("OpenVPN config generated for %s:%d", config.Remote, config.Port)
	return result, nil
}
