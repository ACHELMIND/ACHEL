package web3

import (
	"testing"
)

func TestReentrancyDetect(t *testing.T) {
	engine := NewEngine(Web3Config{
		ChainID: 1,
	})

	result := engine.ReentrancyDetect("0x1234567890abcdef1234567890abcdef12345678")

	if len(result.Vulns) == 0 {
		t.Error("Expected vulnerabilities")
	}
	if result.Vulns[0].Type != "Reentrancy" {
		t.Errorf("Expected Reentrancy vuln, got %s", result.Vulns[0].Type)
	}
}

func TestFlashLoanAttack(t *testing.T) {
	engine := NewEngine(Web3Config{ChainID: 1})

	result := engine.FlashLoanAttack("Aave V3")

	if len(result.FlashLoanPaths) == 0 {
		t.Error("Expected flash loan paths")
	}
	if result.FlashLoanPaths[0].Source == "" {
		t.Error("Source should not be empty")
	}
}

func TestOracleManipulation(t *testing.T) {
	engine := NewEngine(Web3Config{ChainID: 1})

	result := engine.OracleManipulation("0xabcdef1234567890abcdef1234567890abcdef12")

	if len(result.Vulns) == 0 {
		t.Error("Expected vulnerabilities")
	}
	if result.Vulns[0].Type != "Oracle Manipulation" {
		t.Error("Expected Oracle Manipulation vuln")
	}
}

func TestAccessControlBypass(t *testing.T) {
	engine := NewEngine(Web3Config{ChainID: 1})

	result := engine.AccessControlBypass("0x1111111111111111111111111111111111111111")

	if len(result.Vulns) < 2 {
		t.Error("Expected at least 2 vulnerabilities")
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(Web3Config{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
	if engine.config.ChainID != 1 {
		t.Error("Default chain ID should be 1")
	}
}
