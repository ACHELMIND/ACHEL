package arpdhcp

type ARPAttack int

const (
	ARPAttackSpoof ARPAttack = iota
	ARPAttackStorm
	ARPAttackPoison
	ARPAttackGratuitous
)

func (a ARPAttack) String() string {
	return [...]string{"Spoof", "Storm", "Poison", "Gratuitous"}[a]
}

type DHCPServer struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Gateway  string `json:"gateway"`
	DNS      string `json:"dns"`
	Lease    int    `json:"lease_time"`
	Range    string `json:"pool_range"`
}

type ARPPacket struct {
	Operation uint16 `json:"operation"`
	SenderMAC string `json:"sender_mac"`
	SenderIP  string `json:"sender_ip"`
	TargetMAC string `json:"target_mac"`
	TargetIP  string `json:"target_ip"`
}

type ARPDHCPConfig struct {
	Interface   string      `json:"interface"`
	LocalIP     string      `json:"local_ip"`
	LocalMAC    string      `json:"local_mac"`
	TargetIPs   []string    `json:"target_ips"`
	GatewayIP   string      `json:"gateway_ip"`
	ARPAttack   ARPAttack   `json:"arp_attack"`
	DHCPServer  *DHCPServer `json:"dhcp_server,omitempty"`
	NumSpoof    int         `json:"num_spoof"`
	Timeout     int         `json:"timeout"`
}

type ARPDHCPResult struct {
	Attack       ARPAttack  `json:"attack"`
	Success      bool       `json:"success"`
	TargetsPoisoned int     `json:"targets_poisoned"`
	RogueDHCP    bool       `json:"rogue_dhcp"`
	Details      string     `json:"details"`
	PacketsSent  int        `json:"packets_sent"`
	TrafficIntercepted int64 `json:"traffic_intercepted_bytes"`
}

type DHCPLease struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	Lease    int    `json:"lease_time"`
}
