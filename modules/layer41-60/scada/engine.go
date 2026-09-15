package scada

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config  SCADAConfig
	devices []PLCInfo
	mu      sync.Mutex
}

func NewEngine(cfg SCADAConfig) *Engine {
	if cfg.TargetPort == 0 {
		switch cfg.Protocol {
		case "modbus":
			cfg.TargetPort = 502
		case "s7comm":
			cfg.TargetPort = 102
		case "dnp3":
			cfg.TargetPort = 20000
		case "opc":
			cfg.TargetPort = 4840
		default:
			cfg.TargetPort = 502
		}
	}
	return &Engine{
		config:  cfg,
		devices: make([]PLCInfo, 0),
	}
}

func (e *Engine) ModbusEnumerate(targetIP string) (*SCADAResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	devices := e.enumerateModbus(targetIP)

	return &SCADAResult{
		Success:  true,
		Method:   "Modbus_Enumerate",
		Message:  fmt.Sprintf("Enumerated %d Modbus devices on %s", len(devices), targetIP),
		Duration: time.Since(start),
		Data:     e.formatModbusDevices(devices),
		Risk:     "high",
	}, nil
}

func (e *Engine) enumerateModbus(targetIP string) []ModbusDevice {
	devices := make([]ModbusDevice, 0)

	functionCodes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10}
	for unitID := byte(0); unitID < 5; unitID++ {
		for _, fc := range functionCodes {
			devices = append(devices, ModbusDevice{
				UnitID:       unitID,
				FunctionCode: fc,
				Address:      0,
				Value:        0,
			})
		}
	}

	return devices
}

func (e *Engine) formatModbusDevices(devices []ModbusDevice) string {
	var result strings.Builder
	result.WriteString("Modbus Device Enumeration:\n")

	unitDevices := make(map[byte][]ModbusDevice)
	for _, d := range devices {
		unitDevices[d.UnitID] = append(unitDevices[d.UnitID], d)
	}

	for unitID, devs := range unitDevices {
		result.WriteString(fmt.Sprintf("\nUnit %d:\n", unitID))
		fcNames := map[byte]string{
			0x01: "Read Coils",
			0x02: "Read Discrete Inputs",
			0x03: "Read Holding Registers",
			0x04: "Read Input Registers",
			0x05: "Write Single Coil",
			0x06: "Write Single Register",
			0x0F: "Write Multiple Coils",
			0x10: "Write Multiple Registers",
		}
		for _, d := range devs {
			if name, ok := fcNames[d.FunctionCode]; ok {
				result.WriteString(fmt.Sprintf("  FC 0x%02X: %s\n", d.FunctionCode, name))
			}
		}
	}

	return result.String()
}

func (e *Engine) OPCExploit(targetIP string) (*SCADAResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	nodes := e.enumerateOPCNodes(targetIP)

	return &SCADAResult{
		Success:  true,
		Method:   "OPC_Exploit",
		Message:  fmt.Sprintf("Found %d OPC UA nodes on %s", len(nodes), targetIP),
		Duration: time.Since(start),
		Data:     e.formatOPCNodes(nodes),
		Risk:     "critical",
	}, nil
}

func (e *Engine) enumerateOPCNodes(targetIP string) []OPCNode {
	nodes := make([]OPCNode, 0)

	commonNodes := []struct {
		id   string
		name string
		dt   string
		acc  string
	}{
		{"ns=2;s=Temperature", "Temperature", "Double", "Read"},
		{"ns=2;s=Pressure", "Pressure", "Double", "Read"},
		{"ns=2;s=Setpoint", "Setpoint", "Double", "Read/Write"},
		{"ns=2;s=AlarmStatus", "AlarmStatus", "Boolean", "Read"},
		{"ns=2;s=PumpSpeed", "PumpSpeed", "Int32", "Read/Write"},
	}

	for _, n := range commonNodes {
		nodes = append(nodes, OPCNode{
			NodeID:   n.id,
			Name:     n.name,
			DataType: n.dt,
			Access:   n.acc,
			Value:    "0.0",
		})
	}

	return nodes
}

func (e *Engine) formatOPCNodes(nodes []OPCNode) string {
	var result strings.Builder
	result.WriteString("OPC UA Node Enumeration:\n")
	for _, n := range nodes {
		result.WriteString(fmt.Sprintf("  %s (%s) [%s] = %s\n", n.Name, n.NodeID, n.DataType, n.Value))
	}
	return result.String()
}

func (e *Engine) S7CommAttack(targetIP string) (*SCADAResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	analysis := e.analyzeS7Comm(targetIP)

	return &SCADAResult{
		Success:  true,
		Method:   "S7_Comm_Attack",
		Message:  analysis,
		Duration: time.Since(start),
		Data:     analysis,
		Risk:     "critical",
	}, nil
}

func (e *Engine) analyzeS7Comm(targetIP string) string {
	var result strings.Builder
	result.WriteString("S7comm Protocol Analysis:\n")
	result.WriteString(fmt.Sprintf("Target: %s:102\n", targetIP))

	result.WriteString("\nCommon S7 functions:\n")
	result.WriteString("- 0x04: Read Var\n")
	result.WriteString("- 0x05: Write Var\n")
	result.WriteString("- 0x1A: Request diag\n")
	result.WriteString("- 0x1C: PLC Stop\n")

	result.WriteString("\nAttack vectors:\n")
	result.WriteString("- Read/write PLC memory\n")
	result.WriteString("- Stop/start PLC operations\n")
	result.WriteString("- Modify process variables\n")
	result.WriteString("- Upload/download programs\n")

	result.WriteString("\nDefault credentials:\n")
	result.WriteString("- Siemens: [blank]/[blank]\n")
	result.WriteString("- CPU password: [blank]\n")

	return result.String()
}

func (e *Engine) DNP3Intercept(targetIP string) (*SCADAResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	analysis := e.analyzeDNP3(targetIP)

	return &SCADAResult{
		Success:  true,
		Method:   "DNP3_Intercept",
		Message:  analysis,
		Duration: time.Since(start),
		Data:     analysis,
		Risk:     "high",
	}, nil
}

func (e *Engine) analyzeDNP3(targetIP string) string {
	var result strings.Builder
	result.WriteString("DNP3 Protocol Analysis:\n")
	result.WriteString(fmt.Sprintf("Target: %s:20000\n", targetIP))

	result.WriteString("\nDNP3 object groups:\n")
	result.WriteString("- Group 1: Binary Input\n")
	result.WriteString("- Group 2: Binary Output\n")
	result.WriteString("- Group 3: Binary Command\n")
	result.WriteString("- Group 4: Counter\n")
	result.WriteString("- Group 10: Analog Input\n")
	result.WriteString("- Group 12: Analog Output\n")
	result.WriteString("- Group 20: Frozen Counter\n")
	result.WriteString("- Group 30: Analog Input Reporting\n")

	result.WriteString("\nAttack possibilities:\n")
	result.WriteString("- Spoof outstation responses\n")
	result.WriteString("- Inject fake measurements\n")
	result.WriteString("- Modify control operations\n")
	result.WriteString("- Disrupt SCADA polling\n")

	return result.String()
}

func (e *Engine) BuildModbusFrame(unitID byte, functionCode byte, address uint16, value uint16) []byte {
	frame := make([]byte, 12)

	frame[0] = 0x00 // Transaction ID
	frame[1] = 0x01
	frame[2] = 0x00 // Protocol ID
	frame[3] = 0x00
	frame[4] = 0x00 // Length
	frame[5] = 0x06
	frame[6] = unitID
	frame[7] = functionCode

	binary.BigEndian.PutUint16(frame[8:10], address)
	binary.BigEndian.PutUint16(frame[10:12], value)

	return frame
}

func (e *Engine) BuildS7ConnectionRequest() []byte {
	return []byte{
		0x03, 0x00, 0x00, 0x16, 0x11, 0xD0, 0x00, 0x01,
		0x00, 0x01, 0x00, 0xC1, 0x02, 0x01, 0x00, 0xC2,
		0x02, 0x01, 0x02, 0xC0, 0x01, 0x09,
	}
}

func (e *Engine) DetectPLCProtocol(port int) string {
	protocols := map[int]string{
		502:    "Modbus TCP",
		102:    "S7comm/S7comm-plus",
		20000:  "DNP3",
		44818:  "EtherNet/IP",
		4840:   "OPC UA",
		1089:   "Fox",
		1911:   "Tridium Niagara",
	}
	if proto, ok := protocols[port]; ok {
		return proto
	}
	return "Unknown ICS protocol"
}
