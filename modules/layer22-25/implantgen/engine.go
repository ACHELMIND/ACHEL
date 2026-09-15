package implantgen

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
)

type ImplantEngine struct {
	config    *GeneratorConfig
	templates *TemplateManager
	mu        sync.RWMutex
}

func NewImplantEngine(config *GeneratorConfig) *ImplantEngine {
	if config == nil {
		config = NewDefaultGeneratorConfig()
	}
	return &ImplantEngine{
		config:    config,
		templates: NewTemplateManager(),
	}
}

func (e *ImplantEngine) Generate(params *GenerateParams) (*ImplantBinary, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if params.Name == "" {
		return nil, fmt.Errorf("implant name is required")
	}

	arch := params.Arch
	if arch == "" {
		arch = e.config.DefaultArch
	}
	osType := params.OS
	if osType == "" {
		osType = e.config.DefaultOS
	}

	bin, err := e.buildBinary(arch, osType, params)
	if err != nil {
		return nil, fmt.Errorf("build binary: %w", err)
	}

	if params.Encrypt && e.config.EnableEncryption {
		key := params.Key
		if len(key) == 0 {
			key = make([]byte, 32)
			rand.Read(key)
		}
		encrypted, err := encryptPayload(bin, key)
		if err != nil {
			return nil, fmt.Errorf("encrypt payload: %w", err)
		}
		bin = encrypted
	}

	id := uuid.New().String()
	checksum := sha256.Sum256(bin)

	implant := &ImplantBinary{
		ID:         id,
		Data:       bin,
		Size:       len(bin),
		Arch:       arch,
		OS:         osType,
		Encrypted:  params.Encrypt,
		Obfuscated: params.Obfuscate > 0,
		Checksum:   hex.EncodeToString(checksum[:]),
		CreatedAt:  time.Now(),
		Metadata:   params.Metadata,
	}

	return implant, nil
}

func (e *ImplantEngine) EncryptPayload(data []byte, key []byte) ([]byte, error) {
	return encryptPayload(data, key)
}

func (e *ImplantEngine) DecryptPayload(data []byte, key []byte) ([]byte, error) {
	return decryptPayload(data, key)
}

func (e *ImplantEngine) AddTemplate(name string, info TemplateInfo, data []byte) {
	e.templates.Add(name, info, data)
}

func (e *ImplantEngine) GetTemplate(name string) (*TemplateInfo, []byte, bool) {
	return e.templates.Get(name)
}

func (e *ImplantEngine) ListTemplates() []TemplateInfo {
	return e.templates.List()
}

func (e *ImplantEngine) buildBinary(arch Arch, osType OSType, params *GenerateParams) ([]byte, error) {
	var bin []byte

	switch osType {
	case OSWindows:
		bin = e.buildPEHeader(arch, params)
	case OSLinux:
		bin = e.buildELFHeader(arch, params)
	case OSDarwin:
		bin = e.buildMachOHeader(arch, params)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", osType)
	}

	if e.config.MaxBinarySize > 0 && len(bin) > e.config.MaxBinarySize {
		return nil, fmt.Errorf("binary size %d exceeds max %d", len(bin), e.config.MaxBinarySize)
	}

	return bin, nil
}

func (e *ImplantEngine) buildPEHeader(arch Arch, params *GenerateParams) []byte {
	buf := make([]byte, 0, 1024)

	buf = append(buf, 0x4D, 0x5A)

	buf = append(buf, 0x90, 0x00, 0x03, 0x00)

	for i := 0; i < 58; i++ {
		buf = append(buf, 0x00)
	}

	buf = append(buf, 0x80, 0x00)

	peOffset := make([]byte, 4)
	binary.LittleEndian.PutUint32(peOffset, 0x80)
	buf = append(buf, peOffset...)

	peSig := []byte{'P', 'E', 0x00, 0x00}
	buf = append(buf, peSig...)

	coffHeader := make([]byte, 20)
	if arch == ArchX64 || arch == ArchARM64 {
		binary.LittleEndian.PutUint16(coffHeader[0:2], 0x8664)
	} else {
		binary.LittleEndian.PutUint16(coffHeader[0:2], 0x14C)
	}
	binary.LittleEndian.PutUint16(coffHeader[2:4], 1)
	binary.LittleEndian.PutUint32(coffHeader[4:8], 0)
	binary.LittleEndian.PutUint32(coffHeader[8:12], 0)
	binary.LittleEndian.PutUint32(coffHeader[12:16], 0)
	binary.LittleEndian.PutUint16(coffHeader[16:18], 0x0102)
	binary.LittleEndian.PutUint16(coffHeader[18:20], 0x20)
	buf = append(buf, coffHeader...)

	optHeader := make([]byte, 112)
	if arch == ArchX64 || arch == ArchARM64 {
		binary.LittleEndian.PutUint16(optHeader[0:2], 0x020B)
	} else {
		binary.LittleEndian.PutUint16(optHeader[0:2], 0x010B)
	}
	binary.LittleEndian.PutUint32(optHeader[16:20], 0x1000)
	binary.LittleEndian.PutUint32(optHeader[20:24], 0x1000)

	if params.Config != nil {
		configBytes := e.serializeConfig(params.Config)
		buf = append(buf, optHeader...)
		buf = append(buf, configBytes...)
	} else {
		buf = append(buf, optHeader...)
	}

	for i := 0; i < 256; i++ {
		buf = append(buf, 0xCC)
	}

	return buf
}

func (e *ImplantEngine) buildELFHeader(arch Arch, params *GenerateParams) []byte {
	buf := make([]byte, 0, 1024)

	elfMagic := []byte{0x7F, 'E', 'L', 'F'}
	buf = append(buf, elfMagic...)

	if arch == ArchX64 || arch == ArchARM64 {
		buf = append(buf, 2)
	} else {
		buf = append(buf, 1)
	}
	buf = append(buf, 1)

	buf = append(buf, 0, 0, 0, 0)

	eType := make([]byte, 2)
	binary.LittleEndian.PutUint16(eType, 2)
	buf = append(buf, eType...)

	eMachine := make([]byte, 2)
	if arch == ArchX64 {
		binary.LittleEndian.PutUint16(eMachine, 0x3E)
	} else if arch == ArchARM64 {
		binary.LittleEndian.PutUint16(eMachine, 0xB7)
	} else {
		binary.LittleEndian.PutUint16(eMachine, 0x03)
	}
	buf = append(buf, eMachine...)

	for i := 0; i < 32; i++ {
		buf = append(buf, 0)
	}

	phOff := make([]byte, 8)
	binary.LittleEndian.PutUint64(phOff, 64)
	buf = append(buf, phOff...)

	shOff := make([]byte, 8)
	buf = append(buf, shOff...)

	flags := make([]byte, 4)
	buf = append(buf, flags...)

	hdrSize := make([]byte, 2)
	binary.LittleEndian.PutUint16(hdrSize, 64)
	buf = append(buf, hdrSize...)

	if params.Config != nil {
		configBytes := e.serializeConfig(params.Config)
		buf = append(buf, configBytes...)
	}

	for i := 0; i < 256; i++ {
		buf = append(buf, 0xCC)
	}

	return buf
}

func (e *ImplantEngine) buildMachOHeader(arch Arch, params *GenerateParams) []byte {
	buf := make([]byte, 0, 1024)

	magic := make([]byte, 4)
	binary.LittleEndian.PutUint32(magic, 0xFEEDFACF)
	buf = append(buf, magic...)

	cputype := make([]byte, 4)
	if arch == ArchX64 {
		binary.LittleEndian.PutUint32(cputype, 0x01000007)
	} else if arch == ArchARM64 {
		binary.LittleEndian.PutUint32(cputype, 0x0100000C)
	} else {
		binary.LittleEndian.PutUint32(cputype, 0x00000007)
	}
	buf = append(buf, cputype...)

	cpusubtype := make([]byte, 4)
	buf = append(buf, cpusubtype...)

	filetype := make([]byte, 4)
	binary.LittleEndian.PutUint32(filetype, 2)
	buf = append(buf, filetype...)

	for i := 0; i < 20; i++ {
		buf = append(buf, 0)
	}

	if params.Config != nil {
		configBytes := e.serializeConfig(params.Config)
		buf = append(buf, configBytes...)
	}

	for i := 0; i < 256; i++ {
		buf = append(buf, 0xCC)
	}

	return buf
}

func (e *ImplantEngine) serializeConfig(config *BeaconConfig) []byte {
	var buf []byte

	if config.ID != "" {
		buf = append(buf, []byte(config.ID)...)
		buf = append(buf, 0)
	}

	for _, url := range config.CallbackURLs {
		buf = append(buf, []byte(url)...)
		buf = append(buf, 0)
	}

	sleepBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(sleepBytes, uint64(config.SleepTime))
	buf = append(buf, sleepBytes...)

	jitterBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(jitterBytes, uint64(config.Jitter*1000))
	buf = append(buf, jitterBytes...)

	retriesBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(retriesBytes, uint32(config.MaxRetries))
	buf = append(buf, retriesBytes...)

	return buf
}

func (e *ImplantEngine) SetConfig(config *GeneratorConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config = config
}

func (e *ImplantEngine) GetConfig() *GeneratorConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

func encryptPayload(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decryptPayload(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
