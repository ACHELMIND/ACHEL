package memcorrupt

import "testing"

func TestBufferOverflowDetect(t *testing.T) {
	config := MemCorruptConfig{
		TargetBinary: "/usr/bin/test",
		MemoryMap: map[string]uint64{
			"buffer":    0x7fff0000,
			"stack_end": 0x7fff0100,
		},
		BufSize: 256,
		Canary:  false,
		ASLR:    true,
		NX:      true,
	}
	engine := NewEngine(config)
	result := engine.BufferOverflowDetect()
	if result.VulnType != VulnTypeBufferOverflow {
		t.Errorf("expected BufferOverflow vuln type, got %d", result.VulnType)
	}
	if !result.Exploitable {
		t.Error("expected exploitable result")
	}
	if result.Offset == 0 {
		t.Error("expected non-zero offset")
	}
}

func TestUseAfterFree(t *testing.T) {
	config := MemCorruptConfig{
		MemoryMap: map[string]uint64{
			"heap_block_1": 0x600000,
			"heap_block_2": 0x601000,
		},
		BufSize: 128,
	}
	engine := NewEngine(config)
	result := engine.UseAfterFree()
	if result.VulnType != VulnTypeUseAfterFree {
		t.Errorf("expected UseAfterFree, got %d", result.VulnType)
	}
}

func TestHeapSpray(t *testing.T) {
	config := MemCorruptConfig{BufSize: 512}
	engine := NewEngine(config)
	result := engine.HeapSpray()
	if result.VulnType != VulnTypeHeapSpray {
		t.Errorf("expected HeapSpray, got %d", result.VulnType)
	}
	if result.Offset == 0 {
		t.Error("expected non-zero spray size")
	}
}

func TestStackPivot(t *testing.T) {
	config := MemCorruptConfig{
		MemoryMap: map[string]uint64{
			"frame_0": 0x401000,
			"frame_1": 0x401200,
		},
	}
	engine := NewEngine(config)
	result := engine.StackPivot()
	if result.VulnType != VulnTypeStackPivot {
		t.Errorf("expected StackPivot, got %d", result.VulnType)
	}
	if len(result.Techniques) == 0 {
		t.Error("expected non-empty techniques")
	}
}
