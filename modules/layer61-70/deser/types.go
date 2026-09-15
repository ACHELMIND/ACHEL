package deser

type DeserFormat int

const (
	DeserFormatJava DeserFormat = iota
	DeserFormatPython
	DeserFormatPHP
	DeserFormatDotNet
	DeserFormatXML
	DeserFormatYAML
)

func (f DeserFormat) String() string {
	return [...]string{
		"Java", "Python", "PHP", "DotNet", "XML", "YAML",
	}[f]
}

type DeserAttack int

const (
	DeserAttackRCE DeserAttack = iota
	DeserAttackReadFile
	DeserAttackSSRF
	DeserAttackDoS
	DeserAttackDataLeak
)

func (a DeserAttack) String() string {
	return [...]string{
		"RCE", "ReadFile", "SSRF", "DoS", "DataLeak",
	}[a]
}

type DeserConfig struct {
	TargetURL   string            `json:"target_url"`
	Format      DeserFormat       `json:"format"`
	Payload     string            `json:"payload"`
	Headers     map[string]string `json:"headers"`
	GadgetChain []string          `json:"gadget_chain"`
}

type DeserResult struct {
	Format       DeserFormat `json:"format"`
	Attack       DeserAttack `json:"attack"`
	Vulnerable   bool        `json:"vulnerable"`
	Payload      string      `json:"payload"`
	ChainDepth   int         `json:"chain_depth"`
	Details      string      `json:"details"`
	RiskScore    float64     `json:"risk_score"`
}

type Gadget struct {
	Class      string   `json:"class"`
	Methods    []string `json:"methods"`
	Library    string   `json:"library"`
	RiskLevel  int      `json:"risk_level"`
}

type PayloadTemplate struct {
	Name       string      `json:"name"`
	Format     DeserFormat `json:"format"`
	Attack     DeserAttack `json:"attack"`
	Template   string      `json:"template"`
	Variables  []string    `json:"variables"`
}
