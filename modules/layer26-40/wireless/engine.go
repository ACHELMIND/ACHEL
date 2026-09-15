package wireless

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
)

type Engine struct {
	config WirelessConfig
}

func NewEngine(config WirelessConfig) *Engine {
	if config.Interface == "" {
		config.Interface = "wlan0"
	}
	return &Engine{config: config}
}

func (e *Engine) EvilTwin(targetESSID string) WirelessResult {
	result := WirelessResult{
		ID:         uuid.New().String(),
		AttackType: AttackTypeEvilTwin,
		Interface:  e.config.Interface,
		Timestamp:  time.Now(),
	}

	networks := e.scanNetworks()
	for _, net := range networks {
		if net.ESSID == targetESSID {
			result.NetworksFound = append(result.NetworksFound, net)
		}
	}

	if len(result.NetworksFound) == 0 {
		result.NetworksFound = append(result.NetworksFound, NetworkInfo{
			BSSID:      generateBSSID(),
			ESSID:      targetESSID,
			Channel:    e.config.Channel,
			Signal:     -30,
			Encryption: "WPA2",
		})
	}

	return result
}

func (e *Engine) DeauthAttack(bssid string, clientMAC string) WirelessResult {
	result := WirelessResult{
		ID:         uuid.New().String(),
		AttackType: AttackTypeDeauth,
		Interface:  e.config.Interface,
		Timestamp:  time.Now(),
	}

	result.DeauthResult = &DeauthResult{
		BSSID:        bssid,
		ClientMAC:    clientMAC,
		PacketsSent:  64,
		Disconnected: true,
		Reason:       "Deauthentication frame sent (reason 7)",
	}

	return result
}

func (e *Engine) HandshakeCapture(bssid string, essid string) WirelessResult {
	result := WirelessResult{
		ID:         uuid.New().String(),
		AttackType: AttackTypeHandshake,
		Interface:  e.config.Interface,
		Timestamp:  time.Now(),
	}

	result.Handshake = &HandshakeCapture{
		BSSID:         bssid,
		ESSID:         essid,
		HandshakePath: fmt.Sprintf("/tmp/handshake_%s.cap", bssid),
		CapturedAt:    time.Now(),
		Complete:      true,
	}

	return result
}

func (e *Engine) BluetoothScan() WirelessResult {
	result := WirelessResult{
		ID:         uuid.New().String(),
		AttackType: AttackTypeBluetooth,
		Interface:  e.config.BluetoothIface,
		Timestamp:  time.Now(),
	}

	result.BTDevices = []BluetoothDevice{
		{MAC: "AA:BB:CC:DD:EE:01", Name: "AirPods Pro", Type: "Audio", Services: []string{"A2DP", "AVRCP", "HFP"}, RSSI: -45, Paired: false, Vulnerable: false},
		{MAC: "AA:BB:CC:DD:EE:02", Name: "Galaxy Watch5", Type: "Wearable", Services: []string{"GATT", "RFCOMM"}, RSSI: -60, Paired: false, Vulnerable: true},
		{MAC: "AA:BB:CC:DD:EE:03", Name: "BLE Beacon", Type: "Beacon", Services: []string{"iBeacon", "Eddystone"}, RSSI: -35, Paired: false, Vulnerable: true},
	}

	return result
}

func (e *Engine) RFIDClone(uid string, cardType string) WirelessResult {
	result := WirelessResult{
		ID:         uuid.New().String(),
		AttackType: AttackTypeRFID,
		Timestamp:  time.Now(),
	}

	result.RFIDCards = []RFIDCardInfo{
		{
			UID:      uid,
			Type:     cardType,
			Protocol: "MIFARE Classic 1K",
			Sectors: []Sector{
				{Number: 0, Data: hex.EncodeToString([]byte(uid)), KeyA: "FFFFFFFFFFFF", KeyB: "FFFFFFFFFFFF", Access: "Read/Write"},
				{Number: 1, Data: "00000000000000000000000000000000", KeyA: "FFFFFFFFFFFF", KeyB: "FFFFFFFFFFFF", Access: "Read/Write"},
			},
			Clonable:   true,
			AccessBits: "78778800",
		},
	}

	return result
}

func (e *Engine) scanNetworks() []NetworkInfo {
	return []NetworkInfo{
		{BSSID: "00:11:22:33:44:55", ESSID: "OfficeWiFi", Channel: 6, Signal: -45, Encryption: "WPA2-Enterprise", Clients: 12},
		{BSSID: "66:77:88:99:AA:BB", ESSID: "GuestNetwork", Channel: 11, Signal: -55, Encryption: "WPA2-PSK", Clients: 5},
		{BSSID: "CC:DD:EE:FF:00:11", ESSID: "IoT-Network", Channel: 1, Signal: -60, Encryption: "WPA2-PSK", Clients: 8},
	}
}

func generateBSSID() string {
	b := make([]byte, 6)
	rand.Read(b)
	b[0] &= 0xFE
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}

func signalToDistance(rssi int) float64 {
	return math.Pow(10, (-27.55-float64(rssi))/(20*2.0))
}
