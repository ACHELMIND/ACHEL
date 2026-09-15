package memcorrupt

type VulnType int

const (
	VulnTypeBufferOverflow VulnType = iota
	VulnTypeUseAfterFree
	VulnTypeHeapSpray
	VulnTypeStackPivot
	VulnTypeDoubleFree
	VulnTypeFormatString
)

func (v VulnType) String() string {
	return [...]string{
		"BufferOverflow", "UseAfterFree", "HeapSpray",
		"StackPivot", "DoubleFree", "FormatString",
	}[v]
}

type OverflowMethod int

const (
	OverflowMethodStack OverflowMethod = iota
	OverflowMethodHeap
	OverflowMethodBSS
	OverflowMethodData
)

func (o OverflowMethod) String() string {
	return [...]string{"Stack", "Heap", "BSS", "Data"}[o]
}

type MemCorruptConfig struct {
	TargetBinary string            `json:"target_binary"`
	MemoryMap    map[string]uint64 `json:"memory_map"`
	BufSize      int               `json:"buf_size"`
	Canary       bool              `json:"canary"`
	ASLR         bool              `json:"aslr"`
	NX           bool              `json:"nx"`
	PIE          bool              `json:"pie"`
}

type MemCorruptResult struct {
	VulnType       VulnType       `json:"vuln_type"`
	OverflowMethod OverflowMethod `json:"overflow_method"`
	Exploitable    bool           `json:"exploitable"`
	Offset         int            `json:"offset"`
	Details        string         `json:"details"`
	Techniques     []string       `json:"techniques"`
}

type HeapBlock struct {
	Address uint64 `json:"address"`
	Size    int    `json:"size"`
	Freed   bool   `json:"freed"`
	Meta    string `json:"meta"`
}

type StackFrame struct {
	ReturnAddr uint64 `json:"return_addr"`
	SavedBP    uint64 `json:"saved_bp"`
	CanaryVal  uint64 `json:"canary_val"`
	Offset     int    `json:"offset"`
}
