package crypto

type CryptoAttack int

const (
	CryptoAttackPaddingOracle CryptoAttack = iota
	CryptoAttackWeakKey
	CryptoAttackHashLengthExt
	CryptoAttackECBLeak
	CryptoAttackIVReuse
	CryptoAttackKeyReuse
)

func (a CryptoAttack) String() string {
	return [...]string{
		"PaddingOracle", "WeakKey", "HashLengthExt",
		"ECBLeak", "IVReuse", "KeyReuse",
	}[a]
}

type PaddingType int

const (
	PaddingTypePKCS7 PaddingType = iota
	PaddingTypeISO10126
	PaddingTypeANSIX923
	PaddingTypeZero
	PaddingTypeNone
)

func (p PaddingType) String() string {
	return [...]string{"PKCS7", "ISO10126", "ANSIX923", "Zero", "None"}[p]
}

type CryptoConfig struct {
	TargetURL   string       `json:"target_url"`
	Cipher      string       `json:"cipher"`
	PaddingType PaddingType  `json:"padding_type"`
	BlockSize   int          `json:"block_size"`
	KeySize     int          `json:"key_size"`
	IV          []byte       `json:"iv"`
	Ciphertext  []byte       `json:"ciphertext"`
	Plaintext   []byte       `json:"plaintext"`
}

type CryptoResult struct {
	Attack       CryptoAttack `json:"attack"`
	Vulnerable   bool         `json:"vulnerable"`
	BlockSize    int          `json:"block_size"`
	BytesLeaked  int          `json:"bytes_leaked"`
	RiskScore    float64      `json:"risk_score"`
	Details      string       `json:"details"`
	Payload      string       `json:"payload"`
}

type PaddingAnalysis struct {
	ValidPadding    bool   `json:"valid_padding"`
	PaddingType     PaddingType `json:"padding_type"`
	PaddingLength   int    `json:"padding_length"`
	Corrupted       bool   `json:"corrupted"`
}

type ECBAnalysis struct {
	DuplicateBlocks int      `json:"duplicate_blocks"`
	TotalBlocks     int      `json:"total_blocks"`
	LeakageRatio    float64  `json:"leakage_ratio"`
	Patterns        []string `json:"patterns"`
}
