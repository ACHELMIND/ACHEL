package scada

import "time"

type SCADAConfig struct {
	TargetIP    string        `json:"target_ip"`
	TargetPort  int           `json:"target_port"`
	Protocol    string        `json:"protocol"`
	Timeout     time.Duration `json:"timeout"`
}

type SCADAResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Data     string        `json:"data"`
	Risk     string        `json:"risk"`
}

type ICSProtocol struct {
	Name      string `json:"name"`
	Port      int    `json:"port"`
	Version   string `json:"version"`
	Binary    bool   `json:"binary"`
}

type SCADAAttack struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Protocol    string `json:"protocol"`
	Severity    string `json:"severity"`
}

type ModbusDevice struct {
	UnitID      byte   `json:"unit_id"`
	FunctionCode byte  `json:"function_code"`
	Address     uint16 `json:"address"`
	Value       uint16 `json:"value"`
}

type OPCNode struct {
	NodeID    string `json:"node_id"`
	Name      string `json:"name"`
	DataType  string `json:"data_type"`
	Access    string `json:"access"`
	Value     string `json:"value"`
}

type S7Function struct {
	Group    byte   `json:"group"`
	Sequence byte   `json:"sequence"`
	Param    []byte `json:"param"`
	Payload  []byte `json:"payload"`
}

type DNP3Frame struct {
	Start    byte   `json:"start"`
	Length   byte   `json:"length"`
	Control  byte   `json:"control"`
	Dest     byte   `json:"dest"`
	Source   byte   `json:"source"`
	CRC      uint16 `json:"crc"`
}

type PLCInfo struct {
	Vendor    string `json:"vendor"`
	Product   string `json:"product"`
	Firmware  string `json:"firmware"`
	IP        string `json:"ip"`
	Protocol  string `json:"protocol"`
}
