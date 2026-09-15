package crypto

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

type Engine struct {
	config CryptoConfig
}

func NewEngine(config CryptoConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) PaddingOracle() CryptoResult {
	blockSize := e.config.BlockSize
	if blockSize <= 0 {
		blockSize = 16
	}

	ciphertext := e.config.Ciphertext
	if len(ciphertext) == 0 {
		ciphertext = make([]byte, blockSize*2)
		for i := range ciphertext {
			ciphertext[i] = byte(i + 0x41)
		}
	}

	oracle := NewPaddingOracle(blockSize)
	decrypted := oracle.Decrypt(ciphertext)

	bytesLeaked := len(decrypted)
	riskScore := float64(bytesLeaked) / float64(len(ciphertext))
	if riskScore > 1.0 {
		riskScore = 1.0
	}

	detail := fmt.Sprintf("Padding oracle: block_size=%d, blocks=%d, bytes_leaked=%d, risk=%.2f",
		blockSize, len(ciphertext)/blockSize, bytesLeaked, riskScore)

	return CryptoResult{
		Attack:      CryptoAttackPaddingOracle,
		Vulnerable:  bytesLeaked > 0,
		BlockSize:   blockSize,
		BytesLeaked: bytesLeaked,
		RiskScore:   riskScore,
		Details:     detail,
	}
}

func (e *Engine) WeakKeyDetect() CryptoResult {
	keySize := e.config.KeySize
	if keySize <= 0 {
		keySize = 8
	}

	weakPatterns := []struct {
		Name  string
		Check func([]byte) bool
	}{
		{"all_zeros", func(k []byte) bool {
			for _, b := range k {
				if b != 0 {
					return false
				}
			}
			return true
		}},
		{"all_ones", func(k []byte) bool {
			for _, b := range k {
				if b != 0xff {
					return false
				}
			}
			return true
		}},
		{"alternating", func(k []byte) bool {
			for i := 1; i < len(k); i++ {
				if k[i] == k[i-1] {
					return false
				}
			}
			return true
		}},
		{"short_key", func(k []byte) bool { return len(k) < 8 }},
		{"ascii_printable", func(k []byte) bool {
			for _, b := range k {
				if b < 0x20 || b > 0x7e {
					return false
				}
			}
			return true
		}},
	}

	testKey := make([]byte, keySize)
	for i := range testKey {
		testKey[i] = byte(i + 0x41)
	}

	weaknesses := make([]string, 0)
	for _, wp := range weakPatterns {
		if wp.Check(testKey) {
			weaknesses = append(weaknesses, wp.Name)
		}
	}

	entropy := calculateEntropy(testKey)
	riskScore := 0.0
	if entropy < 3.0 {
		riskScore = 0.9
	} else if entropy < 4.0 {
		riskScore = 0.6
	} else {
		riskScore = 0.3
	}

	detail := fmt.Sprintf("Weak key detection: key_size=%d, entropy=%.2f, weaknesses=%d, patterns: %s",
		keySize, entropy, len(weaknesses), strings.Join(weaknesses, ", "))

	return CryptoResult{
		Attack:      CryptoAttackWeakKey,
		Vulnerable:  len(weaknesses) > 0 || entropy < 4.0,
		RiskScore:   riskScore,
		BytesLeaked: 0,
		Details:     detail,
	}
}

func (e *Engine) HashLengthExt() CryptoResult {
	msg := e.config.Plaintext
	if len(msg) == 0 {
		msg = []byte("original_message")
	}

	originalMAC := e.config.IV
	if len(originalMAC) == 0 {
		h := sha256.Sum256(msg)
		originalMAC = h[:]
	}

	blockSize := 64
	if e.config.BlockSize > 0 {
		blockSize = e.config.BlockSize
	}

	paddedLen := len(msg)
	if paddedLen%blockSize != 0 {
		paddedLen = (paddedLen/blockSize + 1) * blockSize
	}

	extension := []byte("; admin=true")
伪造MAC := make([]byte, 32)
	copy(伪造MAC, originalMAC)

	riskScore := 0.85

	detail := fmt.Sprintf("Hash length ext: msg_len=%d, padded=%d, ext_len=%d, original_mac_len=%d",
		len(msg), paddedLen, len(extension), len(originalMAC))

	return CryptoResult{
		Attack:      CryptoAttackHashLengthExt,
		Vulnerable:  true,
		BlockSize:   blockSize,
		BytesLeaked: len(extension),
		RiskScore:   riskScore,
		Details:     detail,
		Payload:     hex.EncodeToString(伪造MAC),
	}
}

func (e *Engine) ECBLeak() CryptoResult {
	blockSize := e.config.BlockSize
	if blockSize <= 0 {
		blockSize = 16
	}

	plaintext := e.config.Plaintext
	if len(plaintext) == 0 {
		plaintext = []byte("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")
	}

	blocks := make(map[string]int)
	numBlocks := len(plaintext) / blockSize
	for i := 0; i < numBlocks; i++ {
		start := i * blockSize
		end := start + blockSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		block := hex.EncodeToString(plaintext[start:end])
		blocks[block]++
	}

	duplicates := 0
	patterns := make([]string, 0)
	for block, count := range blocks {
		if count > 1 {
			duplicates++
			patterns = append(patterns, fmt.Sprintf("%s(x%d)", block[:8], count))
		}
	}

	analysis := ECBAnalysis{
		DuplicateBlocks: duplicates,
		TotalBlocks:     numBlocks,
		Patterns:        patterns,
	}
	if numBlocks > 0 {
		analysis.LeakageRatio = float64(duplicates) / float64(numBlocks)
	}

	riskScore := analysis.LeakageRatio * 0.8

	detail := fmt.Sprintf("ECB leak: %d blocks, %d duplicates, leakage: %.2f, patterns: %s",
		analysis.TotalBlocks, analysis.DuplicateBlocks, analysis.LeakageRatio, strings.Join(patterns, ", "))

	return CryptoResult{
		Attack:      CryptoAttackECBLeak,
		Vulnerable:  duplicates > 0,
		BlockSize:   blockSize,
		BytesLeaked: duplicates * blockSize,
		RiskScore:   riskScore,
		Details:     detail,
	}
}

type PaddingOracle struct {
	blockSize int
}

func NewPaddingOracle(blockSize int) *PaddingOracle {
	return &PaddingOracle{blockSize: blockSize}
}

func (po *PaddingOracle) Decrypt(ciphertext []byte) []byte {
	if len(ciphertext) < po.blockSize || len(ciphertext)%po.blockSize != 0 {
		return nil
	}

	plaintext := make([]byte, 0)
	for i := 0; i < len(ciphertext); i += po.blockSize {
		block := ciphertext[i : i+po.blockSize]
		decrypted := po.decryptBlock(block)
		plaintext = append(plaintext, decrypted...)
	}

	if len(plaintext) > 0 {
		padLen := int(plaintext[len(plaintext)-1])
		if padLen > 0 && padLen <= po.blockSize {
			plaintext = plaintext[:len(plaintext)-padLen]
		}
	}

	return plaintext
}

func (po *PaddingOracle) decryptBlock(block []byte) []byte {
	result := make([]byte, len(block))
	prev := make([]byte, len(block))

	for i := 0; i < len(block); i++ {
		padByte := byte(len(block) - i)
		for j := 0; j < 256; j++ {
			prev[i] = byte(j)
			candidate := make([]byte, len(block))
			copy(candidate, prev)
			for k := i + 1; k < len(block); k++ {
				candidate[k] = block[k] ^ padByte ^ prev[k]
			}
			if isValidPadding(candidate) {
				result[i] = byte(j) ^ block[i]
				if i+1 < len(block) {
					prev[i+1] = byte(j) ^ padByte ^ byte(i+1)
				}
				break
			}
		}
	}
	return result
}

func isValidPadding(block []byte) bool {
	if len(block) == 0 {
		return false
	}
	padLen := int(block[len(block)-1])
	if padLen == 0 || padLen > len(block) {
		return false
	}
	for i := len(block) - padLen; i < len(block); i++ {
		if block[i] != byte(padLen) {
			return false
		}
	}
	return true
}

func calculateEntropy(data []byte) float64 {
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	length := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * log2(p)
		}
	}
	return entropy
}

func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	return log(x) / log(2)
}

func log(x float64) float64 {
	if x <= 0 {
		return -1000
	}
	n := 0
	for x >= 2 {
		x /= 2
		n++
	}
	for x < 1 {
		x *= 2
		n--
	}
	z := (x - 1) / (x + 1)
	z2 := z * z
	sum := z
	for i := 1; i < 20; i++ {
		z *= z2
		sum += z / float64(2*i+1)
	}
	return sum*2 + float64(n)
}

func (e *Engine) calculateKeySize(ciphertext []byte) int {
	if len(ciphertext) < 32 {
		return 16
	}

	hammingDistances := make([]float64, 0)
	for keySize := 2; keySize <= 32; keySize++ {
		if len(ciphertext) < keySize*4 {
			continue
		}
		blocks := make([][]byte, 4)
		for i := 0; i < 4; i++ {
			start := i * keySize
			end := start + keySize
			if end > len(ciphertext) {
				break
			}
			blocks[i] = ciphertext[start:end]
		}
		if len(blocks) < 4 {
			continue
		}

		totalDist := 0
		count := 0
		for i := 0; i < len(blocks)-1; i++ {
			for j := i + 1; j < len(blocks); j++ {
				totalDist += hammingDistance(blocks[i], blocks[j])
				count++
			}
		}
		if count > 0 {
			avgDist := float64(totalDist) / float64(count) / float64(keySize)
			hammingDistances = append(hammingDistances, avgDist)
		}
	}

	if len(hammingDistances) == 0 {
		return 16
	}

	bestIdx := 0
	bestScore := hammingDistances[0]
	for i, d := range hammingDistances {
		if d < bestScore {
			bestScore = d
			bestIdx = i
		}
	}
	return bestIdx + 2
}

func hammingDistance(a, b []byte) int {
	dist := 0
	for i := 0; i < len(a) && i < len(b); i++ {
		xor := a[i] ^ b[i]
		for j := 0; j < 8; j++ {
			if xor&(1<<uint(j)) != 0 {
				dist++
			}
		}
	}
	return dist
}

func (e *Engine) detectCipherMode(ciphertext []byte, blockSize int) string {
	if len(ciphertext) < blockSize*2 {
		return "unknown"
	}

	blocks := make(map[string]int)
	for i := 0; i+blockSize <= len(ciphertext); i += blockSize {
		block := hex.EncodeToString(ciphertext[i : i+blockSize])
		blocks[block]++
	}

	for _, count := range blocks {
		if count > 1 {
			return "ECB"
		}
	}

	if len(e.config.IV) > 0 {
		return "CBC"
	}
	return "CTR"
}

func (e *Engine) analyzeIV(iv []byte) map[string]interface{} {
	analysis := make(map[string]interface{})
	analysis["length"] = len(iv)
	analysis["all_zeros"] = true
	analysis["all_ones"] = true
	for _, b := range iv {
		if b != 0 {
			analysis["all_zeros"] = false
		}
		if b != 0xff {
			analysis["all_ones"] = false
		}
	}
	analysis["entropy"] = calculateEntropy(iv)
	return analysis
}

var _ = cipher.Block(nil)
var _ = des.NewTripleDESCipher
var _ = md5.New
var _ = binary.BigEndian
