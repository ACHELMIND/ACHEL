package memcorrupt

import (
	"fmt"
	"math/rand"
	"strings"
)

type Engine struct {
	config MemCorruptConfig
}

func NewEngine(config MemCorruptConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) BufferOverflowDetect() MemCorruptResult {
	bufSize := e.config.BufSize
	if bufSize <= 0 {
		bufSize = 256
	}

	offset := 0
	method := OverflowMethodStack
	exploitable := false

	if e.config.MemoryMap != nil {
		if stackEnd, ok := e.config.MemoryMap["stack_end"]; ok {
			if buf, ok := e.config.MemoryMap["buffer"]; ok {
				diff := int(stackEnd - buf)
				if diff > 0 && diff < 1024 {
					offset = diff
					exploitable = true
				}
			}
		}
		if heapStart, ok := e.config.MemoryMap["heap_start"]; ok {
			if buf, ok := e.config.MemoryMap["buffer"]; ok {
				if buf > heapStart {
					method = OverflowMethodHeap
					offset = int(buf - heapStart)
					exploitable = offset < 4096
				}
			}
		}
	}

	if offset == 0 {
		offset = bufSize + 8
		method = OverflowMethodStack
		exploitable = !e.config.Canary
	}

	techniques := []string{"pattern_create", "pattern_offset"}
	if exploitable {
		techniques = append(techniques, "shellcode_inject")
		if !e.config.NX {
			techniques = append(techniques, "nop_sled")
		}
	}
	if e.config.Canary {
		techniques = append(techniques, "canary_leak", "stack_smash")
	}
	if !e.config.ASLR {
		techniques = append(techniques, "ret2libc")
	}
	if e.config.PIE {
		techniques = append(techniques, "info_leak", "base_offset")
	}

	detail := fmt.Sprintf("Buffer size: %d, overflow offset: %d, method: %s, canary: %v, NX: %v",
		bufSize, offset, method, e.config.Canary, e.config.NX)

	return MemCorruptResult{
		VulnType:       VulnTypeBufferOverflow,
		OverflowMethod: method,
		Exploitable:    exploitable,
		Offset:         offset,
		Details:        detail,
		Techniques:     techniques,
	}
}

func (e *Engine) UseAfterFree() MemCorruptResult {
	blocks := make([]HeapBlock, 0)
	if e.config.MemoryMap != nil {
		for k, v := range e.config.MemoryMap {
			if strings.HasPrefix(k, "heap_block_") {
				blocks = append(blocks, HeapBlock{
					Address: v,
					Size:    64,
					Freed:   rand.Intn(2) == 0,
				})
			}
		}
	}

	freedCount := 0
	for _, b := range blocks {
		if b.Freed {
			freedCount++
		}
	}

	exploitable := freedCount > 0
	offset := 0
	if len(blocks) > 0 {
		for i, b := range blocks {
			if b.Freed && i+1 < len(blocks) {
				offset = int(blocks[i+1].Address - b.Address)
				break
			}
		}
	}
	if offset == 0 {
		offset = 64
	}

	techniques := []string{"heap_groom", "use_after_free_alloc"}
	if exploitable {
		techniques = append(techniques, "uaf_deref", "function_ptr_overwrite")
	}

	detail := fmt.Sprintf("Heap blocks analyzed: %d, freed: %d, exploitability: %v",
		len(blocks), freedCount, exploitable)

	return MemCorruptResult{
		VulnType:    VulnTypeUseAfterFree,
		Exploitable: exploitable,
		Offset:      offset,
		Details:     detail,
		Techniques:  techniques,
	}
}

func (e *Engine) HeapSpray() MemCorruptResult {
	bufSize := e.config.BufSize
	if bufSize <= 0 {
		bufSize = 256
	}

	blocksNeeded := 128
	spraySize := blocksNeeded * bufSize
	sprayAddresses := make([]uint64, 0)

	baseAddr := uint64(0x0a0a0a0a)
	for i := 0; i < blocksNeeded; i++ {
		addr := baseAddr + uint64(i*bufSize)
		sprayAddresses = append(sprayAddresses, addr)
	}

	alignment := bufSize % 4
	exploitable := alignment == 0 && spraySize > 0

	techniques := []string{"heap_spray", "nop_sled_alloc"}
	if exploitable {
		techniques = append(techniques, "heap_spatter", "landing_pad")
	}

	detail := fmt.Sprintf("Spray: %d blocks x %d bytes = %d total, alignment: %d, addresses: %d",
		blocksNeeded, bufSize, spraySize, alignment, len(sprayAddresses))

	return MemCorruptResult{
		VulnType:    VulnTypeHeapSpray,
		Exploitable: exploitable,
		Offset:      spraySize,
		Details:     detail,
		Techniques:  techniques,
	}
}

func (e *Engine) StackPivot() MemCorruptResult {
	exploitable := false
	offset := 0

	frames := make([]StackFrame, 0)
	if e.config.MemoryMap != nil {
		for k, v := range e.config.MemoryMap {
			if strings.HasPrefix(k, "frame_") {
				frames = append(frames, StackFrame{
					ReturnAddr: v,
					SavedBP:    v + 0x10,
					Offset:     len(frames) * 8,
				})
			}
		}
	}

	if len(frames) == 0 {
		frames = append(frames, StackFrame{ReturnAddr: 0x401000, SavedBP: 0x7fff0000, Offset: 0})
		frames = append(frames, StackFrame{ReturnAddr: 0x401200, SavedBP: 0x7fff0020, Offset: 8})
	}

	for _, f := range frames {
		if f.ReturnAddr != 0 {
			offset = f.Offset + 8
			exploitable = true
			break
		}
	}

	techniques := []string{"stack_pivot"}
	if exploitable {
		techniques = append(techniques, "rop_chain", "pivot_to_heap")
		if !e.config.NX {
			techniques = append(techniques, "shellcode_chain")
		}
	}

	detail := fmt.Sprintf("Stack frames: %d, pivot offset: %d, canary present: %v",
		len(frames), offset, e.config.Canary)

	return MemCorruptResult{
		VulnType:    VulnTypeStackPivot,
		Exploitable: exploitable,
		Offset:      offset,
		Details:     detail,
		Techniques:  techniques,
	}
}
