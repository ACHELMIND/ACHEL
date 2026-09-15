package scada

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(SCADAConfig{
		TargetIP:   "192.168.1.100",
		TargetPort: 502,
		Protocol:   "modbus",
	})
}

func TestModbusEnumerate(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.ModbusEnumerate("192.168.1.100")
	if err != nil {
		t.Fatalf("ModbusEnumerate failed: %v", err)
	}
	if !result.Success {
		t.Error("ModbusEnumerate reported failure")
	}
	if result.Method != "Modbus_Enumerate" {
		t.Errorf("expected method Modbus_Enumerate, got %s", result.Method)
	}
	if len(result.Data) == 0 {
		t.Error("data is empty")
	}
}

func TestOPCExploit(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.OPCExploit("192.168.1.100")
	if err != nil {
		t.Fatalf("OPCExploit failed: %v", err)
	}
	if !result.Success {
		t.Error("OPCExploit reported failure")
	}
	if result.Method != "OPC_Exploit" {
		t.Errorf("expected method OPC_Exploit, got %s", result.Method)
	}
}

func TestS7CommAttack(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.S7CommAttack("192.168.1.100")
	if err != nil {
		t.Fatalf("S7CommAttack failed: %v", err)
	}
	if !result.Success {
		t.Error("S7CommAttack reported failure")
	}
	if !strings.Contains(result.Data, "S7comm") {
		t.Error("should mention S7comm")
	}
}

func TestDNP3Intercept(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.DNP3Intercept("192.168.1.100")
	if err != nil {
		t.Fatalf("DNP3Intercept failed: %v", err)
	}
	if !result.Success {
		t.Error("DNP3Intercept reported failure")
	}
	if !strings.Contains(result.Data, "DNP3") {
		t.Error("should mention DNP3")
	}
}

func TestBuildModbusFrame(t *testing.T) {
	eng := newTestEngine()
	frame := eng.BuildModbusFrame(0x01, 0x03, 0x0000, 0x000A)
	if len(frame) != 12 {
		t.Errorf("expected 12 bytes, got %d", len(frame))
	}
	if frame[6] != 0x01 {
		t.Errorf("expected unit ID 0x01, got 0x%02x", frame[6])
	}
	if frame[7] != 0x03 {
		t.Errorf("expected FC 0x03, got 0x%02x", frame[7])
	}
}

func TestBuildS7ConnectionRequest(t *testing.T) {
	eng := newTestEngine()
	pkt := eng.BuildS7ConnectionRequest()
	if len(pkt) == 0 {
		t.Error("S7 connection request should not be empty")
	}
	if pkt[0] != 0x03 {
		t.Errorf("expected TPKT version 3, got %d", pkt[0])
	}
}

func TestDetectPLCProtocol(t *testing.T) {
	eng := newTestEngine()
	tests := []struct {
		port int
		want string
	}{
		{502, "Modbus TCP"},
		{102, "S7comm"},
		{20000, "DNP3"},
		{4840, "OPC UA"},
		{9999, "Unknown"},
	}
	for _, tt := range tests {
		got := eng.DetectPLCProtocol(tt.port)
		if !strings.Contains(got, tt.want) {
			t.Errorf("DetectPLCProtocol(%d) = %s, want %s", tt.port, got, tt.want)
		}
	}
}

func TestDefaultPortModbus(t *testing.T) {
	eng := NewEngine(SCADAConfig{TargetIP: "10.0.0.1", Protocol: "modbus"})
	if eng.config.TargetPort != 502 {
		t.Errorf("expected default modbus port 502, got %d", eng.config.TargetPort)
	}
}

func TestDefaultPortS7(t *testing.T) {
	eng := NewEngine(SCADAConfig{TargetIP: "10.0.0.1", Protocol: "s7comm"})
	if eng.config.TargetPort != 102 {
		t.Errorf("expected default s7 port 102, got %d", eng.config.TargetPort)
	}
}

func TestDefaultPortDNP3(t *testing.T) {
	eng := NewEngine(SCADAConfig{TargetIP: "10.0.0.1", Protocol: "dnp3"})
	if eng.config.TargetPort != 20000 {
		t.Errorf("expected default dnp3 port 20000, got %d", eng.config.TargetPort)
	}
}
