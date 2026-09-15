package physical

import "time"

type USBAttackType int

const (
	USBAttackTypeHID USBAttackType = iota
	USBAttackTypeStorage
	USBAttackTypeNetwork
	USBAttackTypeBadUSB
	USBAttackTypeRubberDucky
	USBAttackTypeOMG
)

func (u USBAttackType) String() string {
	return [...]string{"HID", "Storage", "Network", "BadUSB", "RubberDucky", "O.MG"}[u]

}

type PhysicalConfig struct {
	USBDropCount   int
	USBPayload     string
	BadgeType      string
	BadgeUID       string
	LockType       string
	NetworkTapType string
	TargetLocation string
	PersistLog     string
}

type PhysicalResult struct {
	ID            string            `json:"id"`
	USBDrops      []USBDropResult   `json:"usb_drops"`
	BadgeClones   []BadgeCloneResult `json:"badge_clones"`
	LockResults   []LockResult      `json:"lock_results"`
	NetworkTaps   []NetworkTapResult `json:"network_taps"`
	Timestamp     time.Time         `json:"timestamp"`
}

type USBDropResult struct {
	ID          string        `json:"id"`
	USBType     USBAttackType `json:"usb_type"`
	Location    string        `json:"location"`
	PickedUp    bool          `json:"picked_up"`
	Connected   bool          `json:"connected"`
	Executed    bool          `json:"executed"`
	PayloadHash string        `json:"payload_hash"`
}

type BadgeCloneResult struct {
	OriginalUID   string `json:"original_uid"`
	ClonedUID     string `json:"cloned_uid"`
	BadgeType     string `json:"badge_type"`
	Protocol      string `json:"protocol"`
	Success       bool   `json:"success"`
	AccessGranted bool   `json:"access_granted"`
}

type BadgeConfig struct {
	ReaderType    string
	WriterType    string
	CloneAll      bool
	FacilityCode  int
	BitLength     int
}

type LockResult struct {
	LockType      string `json:"lock_type"`
	Method        string `json:"method"`
	Success       bool   `json:"success"`
	TimeSeconds   int    `json:"time_seconds"`
	Details       string `json:"details"`
}

type NetworkTapResult struct {
	Type          string `json:"type"`
	Location      string `json:"location"`
	Active        bool   `json:"active"`
	PacketsCaptured int  `json:"packets_captured"`
	Interfaces    []string `json:"interfaces"`
}
