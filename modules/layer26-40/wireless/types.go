package wireless

import "time"

type AttackType int

const (
	AttackTypeEvilTwin AttackType = iota
	AttackTypeDeauth
	AttackTypeHandshake
	AttackTypeWPS
	AttackTypePMKID
	AttackTypeKarma
	AttackTypeBluetooth
	AttackTypeRFID
)

func (a AttackType) String() string {
	return [...]string{
		"EvilTwin", "Deauth", "Handshake", "WPS",
		"PMKID", "Karma", "Bluetooth", "RFID",
	}[a]
}

type WirelessConfig struct {
	Interface     string
	MonitorMode   bool
	Channel       int
	BSSID         string
	ESSID         string
	Wordlist      string
	Timeout       time.Duration
	TargetAP      string
	BluetoothIface string
	RFIDReader    string
}

type WirelessResult struct {
	ID            string              `json:"id"`
	AttackType    AttackType          `json:"attack_type"`
	Interface     string              `json:"interface"`
	NetworksFound []NetworkInfo       `json:"networks_found"`
	Handshake     *HandshakeCapture   `json:"handshake,omitempty"`
	DeauthResult  *DeauthResult       `json:"deauth_result,omitempty"`
	BTDevices     []BluetoothDevice   `json:"bluetooth_devices"`
	RFIDCards     []RFIDCardInfo      `json:"rfid_cards"`
	Timestamp     time.Time           `json:"timestamp"`
}

type NetworkInfo struct {
	BSSID      string `json:"bssid"`
	ESSID      string `json:"essid"`
	Channel    int    `json:"channel"`
	Signal     int    `json:"signal"`
	Encryption string `json:"encryption"`
	Clients    int    `json:"clients"`
}

type HandshakeCapture struct {
	BSSID       string    `json:"bssid"`
	ESSID       string    `json:"essid"`
	HandshakePath string  `json:"handshake_path"`
	CapturedAt  time.Time `json:"captured_at"`
	PMKID       string    `json:"pmkid,omitempty"`
	Complete    bool      `json:"complete"`
}

type DeauthResult struct {
	BSSID         string `json:"bssid"`
	ClientMAC     string `json:"client_mac"`
	PacketsSent   int    `json:"packets_sent"`
	Disconnected  bool   `json:"disconnected"`
	Reason        string `json:"reason"`
}

type BluetoothDevice struct {
	MAC        string            `json:"mac"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Services   []string          `json:"services"`
	RSSI       int               `json:"rssi"`
	Paired     bool              `json:"paired"`
	Vulnerable bool              `json:"vulnerable"`
	Properties map[string]string `json:"properties"`
}

type RFIDCardInfo struct {
	UID         string   `json:"uid"`
	Type        string   `json:"type"`
	Protocol    string   `json:"protocol"`
	Sectors     []Sector `json:"sectors"`
	Clonable    bool     `json:"clonable"`
	AccessBits  string   `json:"access_bits"`
}

type Sector struct {
	Number   int    `json:"number"`
	Data     string `json:"data"`
	KeyA     string `json:"key_a"`
	KeyB     string `json:"key_b"`
	Access   string `json:"access"`
}

type BluetoothConfig struct {
	Interface   string
	ScanDuration time.Duration
	Pairable    bool
	ScanMode    string
}
