package physical

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"time"

	"github.com/google/uuid"
)

type Engine struct {
	config PhysicalConfig
}

func NewEngine(config PhysicalConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) USBDrop(count int) PhysicalResult {
	result := PhysicalResult{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
	}

	for i := 0; i < count; i++ {
		drop := USBDropResult{
			ID:          uuid.New().String(),
			USBType:     USBAttackTypeHID,
			Location:    e.selectLocation(),
			PickedUp:    true,
			Connected:   true,
			Executed:    true,
			PayloadHash: generatePayloadHash(),
		}
		result.USBDrops = append(result.USBDrops, drop)
	}

	return result
}

func (e *Engine) BadgeClone(originalUID string) PhysicalResult {
	result := PhysicalResult{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
	}

	clone := BadgeCloneResult{
		OriginalUID:   originalUID,
		ClonedUID:     originalUID,
		BadgeType:     "HID ProxCard II",
		Protocol:      "125kHz Proximity",
		Success:       true,
		AccessGranted: true,
	}

	result.BadgeClones = append(result.BadgeClones, clone)

	clone2 := BadgeCloneResult{
		OriginalUID:   "04:A2:3B:C1:D5:6E:80",
		ClonedUID:     "04:A2:3B:C1:D5:6E:80",
		BadgeType:     "MIFARE DESFire EV2",
		Protocol:      "13.56MHz Contactless",
		Success:       true,
		AccessGranted: true,
	}
	result.BadgeClones = append(result.BadgeClones, clone2)

	return result
}

func (e *Engine) LockPicking(lockType string) PhysicalResult {
	result := PhysicalResult{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
	}

	locks := []LockResult{
		{LockType: "Pin Tumbler (Standard)", Method: "Raking + BOK tension", Success: true, TimeSeconds: 15, Details: "4-pin residential lock picked with bogota rake"},
		{LockType: "Pin Tumbler (High Security)", Method: "SPP with custom picks", Success: true, TimeSeconds: 180, Details: "6-pin Mul-T-Lock picked via single pin picking"},
		{LockType: "Wafer Lock", Method: "Shim tool", Success: true, TimeSeconds: 5, Details: "File cabinet wafer lock opened with tension wrench"},
		{LockType: "Disc Detainer", Method: "Disc pick + tension", Success: false, TimeSeconds: 300, Details: "Abloy Protec2 requires specialized tools"},
		{LockType: "Smart Lock (Z-Wave)", Method: "Rolling code replay", Success: true, TimeSeconds: 30, Details: "Captured and replayed unlock command via SDR"},
	}

	result.LockResults = locks
	return result
}

func (e *Engine) NetworkTap(location string) PhysicalResult {
	result := PhysicalResult{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
	}

	taps := []NetworkTapResult{
		{
			Type:          "Inline Tap (Network Tap)",
			Location:      location,
			Active:        true,
			PacketsCaptured: 15000,
			Interfaces:    []string{"eth0", "eth1"},
		},
		{
			Type:          "ARP Spoofing",
			Location:      location,
			Active:        true,
			PacketsCaptured: 8500,
			Interfaces:    []string{"wlan0"},
		},
		{
			Type:          "Span Port Mirror",
			Location:      location,
			Active:        true,
			PacketsCaptured: 45000,
			Interfaces:    []string{"span0"},
		},
	}

	result.NetworkTaps = taps
	return result
}

func (e *Engine) selectLocation() string {
	locations := []string{"Reception Desk", "Conference Room A", "Parking Garage", "Break Room", "Server Room Door"}
	return locations[time.Now().UnixNano()%int64(len(locations))]
}

func generatePayloadHash() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	length := float64(len(data))
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
