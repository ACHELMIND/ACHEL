package web3

import "time"

type SmartContract struct {
	Address     string   `json:"address"`
	ABI         string   `json:"abi"`
	Compiler    string   `json:"compiler"`
	Version     string   `json:"version"`
	SourceCode  string   `json:"source_code"`
	Balance     string   `json:"balance"`
	Functions   []string `json:"functions"`
}

type DeFiProtocol struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Address  string `json:"address"`
	TVL      string `json:"tvl"`
	Chains   []string `json:"chains"`
}

type Web3Config struct {
	RPCURL          string
	ChainID         int
	ContractAddress string
	PrivateKey      string
	GasPrice        string
	DeFiProtocols   []DeFiProtocol
	Contracts       []SmartContract
}

type Web3Result struct {
	ID                string              `json:"id"`
	Contracts         []ContractAnalysis  `json:"contracts"`
	Vulns             []ContractVuln      `json:"vulnerabilities"`
	DeFiExploits      []DeFiExploit       `json:"defi_exploits"`
	FlashLoanPaths    []FlashLoanPath     `json:"flash_loan_paths"`
	Timestamp         time.Time           `json:"timestamp"`
}

type ContractAnalysis struct {
	Address       string   `json:"address"`
	Functions     []FuncInfo `json:"functions"`
	VulnCount     int      `json:"vuln_count"`
	RiskScore     int      `json:"risk_score"`
}

type FuncInfo struct {
	Name      string   `json:"name"`
	Selector  string   `json:"selector"`
	Mutability string `json:"mutability"`
	Payable    bool    `json:"payable"`
}

type ContractVuln struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Location    string `json:"location"`
	Description string `json:"description"`
	Fix         string `json:"fix"`
}

type DeFiExploit struct {
	Protocol    string   `json:"protocol"`
	Type        string   `json:"type"`
	Amount      string   `json:"amount"`
	Payload     string   `json:"payload"`
	Steps       []string `json:"steps"`
}

type FlashLoanPath struct {
	Source      string   `json:"source"`
	Target      string   `json:"target"`
	Steps       []string `json:"steps"`
	Profit      string   `json:"profit"`
	GasCost     string   `json:"gas_cost"`
}
