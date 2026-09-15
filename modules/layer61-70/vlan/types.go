package vlan

type VLANAttack int

const (
	VLANAttackDoubleTagging VLANAttack = iota
	VLANAttackSwitchSpoofing
	VLANAttackVLANGrafting
	VLANAttackTrunkNegotiation
	VLANAttackSTPManip
)

func (a VLANAttack) String() string {
	return [...]string{
		"DoubleTagging", "SwitchSpoofing", "VLANGrafting",
		"TrunkNegotiation", "STPManip",
	}[a]
}

type TagConfig struct {
	OuterVLAN int    `json:"outer_vlan"`
	InnerVLAN int    `json:"inner_vlan"`
	Priority  int    `json:"priority"`
	TPID      uint16 `json:"tpid"`
}

type VLANConfig struct {
	Interface     string    `json:"interface"`
	SourceVLAN    int       `json:"source_vlan"`
	TargetVLAN    int       `json:"target_vlan"`
	AttackType    VLANAttack `json:"attack_type"`
	TagConfig     TagConfig `json:"tag_config"`
	PacketsToSend int       `json:"packets_to_send"`
	MACSource     string    `json:"mac_source"`
	MACDest       string    `json:"mac_dest"`
}

type VLANResult struct {
	Attack       VLANAttack `json:"attack"`
	Success      bool       `json:"success"`
	PacketsSent  int        `json:"packets_sent"`
	VLANLeaked   int        `json:"vlan_leaked"`
	Details      string     `json:"details"`
	FrameHex     string     `json:"frame_hex"`
	Tags         []TagConfig `json:"tags"`
}

type EthernetFrame struct {
	DestMAC    string `json:"dest_mac"`
	SrcMAC     string `json:"src_mac"`
	VLAN1      int    `json:"vlan_1"`
	VLAN2      int    `json:"vlan_2"`
	EtherType  uint16 `json:"ether_type"`
	Payload    []byte `json:"payload"`
}
