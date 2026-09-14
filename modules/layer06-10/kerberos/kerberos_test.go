package kerberos

import (
	"testing"
	"time"
)

func TestKerberosEngineCreation(t *testing.T) {
	engine := NewKerberosEngine(nil)
	if engine == nil {
		t.Fatal("Expected non-nil engine")
	}
	if engine.config == nil {
		t.Fatal("Expected non-nil config")
	}
	if engine.config.Domain != "CORP.LOCAL" {
		t.Errorf("Expected domain CORP.LOCAL, got %s", engine.config.Domain)
	}
}

func TestGoldenTicket(t *testing.T) {
	engine := NewKerberosEngine(nil)

	ticket, err := engine.GoldenTicket("CORP.LOCAL", "aad3b435b51404eeaad3b435b51404ee")
	if err != nil {
		t.Fatalf("GoldenTicket failed: %v", err)
	}
	if ticket == nil {
		t.Fatal("Expected non-nil ticket")
	}
	if ticket.TicketVNO != 5 {
		t.Errorf("Expected ticket version 5, got %d", ticket.TicketVNO)
	}
	if ticket.Realm != "CORP.LOCAL" {
		t.Errorf("Expected realm CORP.LOCAL, got %s", ticket.Realm)
	}
}

func TestGoldenTicketEmptyDomain(t *testing.T) {
	engine := NewKerberosEngine(nil)
	_, err := engine.GoldenTicket("", "aad3b435b51404eeaad3b435b51404ee")
	if err == nil {
		t.Error("Expected error for empty domain")
	}
}

func TestGoldenTicketEmptyHash(t *testing.T) {
	engine := NewKerberosEngine(nil)
	_, err := engine.GoldenTicket("CORP.LOCAL", "")
	if err == nil {
		t.Error("Expected error for empty hash")
	}
}

func TestSilverTicket(t *testing.T) {
	engine := NewKerberosEngine(nil)

	ticket, err := engine.SilverTicket("CORP.LOCAL", "aad3b435b51404eeaad3b435b51404ee", "HTTP/web01.corp.local")
	if err != nil {
		t.Fatalf("SilverTicket failed: %v", err)
	}
	if ticket == nil {
		t.Fatal("Expected non-nil ticket")
	}
	if ticket.TicketVNO != 5 {
		t.Errorf("Expected ticket version 5, got %d", ticket.TicketVNO)
	}
}

func TestSilverTicketEmptyFields(t *testing.T) {
	engine := NewKerberosEngine(nil)

	_, err := engine.SilverTicket("", "aad3b435b51404eeaad3b435b51404ee", "HTTP/web01.corp.local")
	if err == nil {
		t.Error("Expected error for empty domain")
	}

	_, err = engine.SilverTicket("CORP.LOCAL", "", "HTTP/web01.corp.local")
	if err == nil {
		t.Error("Expected error for empty hash")
	}

	_, err = engine.SilverTicket("CORP.LOCAL", "aad3b435b51404eeaad3b435b51404ee", "")
	if err == nil {
		t.Error("Expected error for empty SPN")
	}
}

func TestDiamondTicket(t *testing.T) {
	engine := NewKerberosEngine(nil)

	ticket, err := engine.DiamondTicket("CORP.LOCAL", "aad3b435b51404eeaad3b435b51404ee")
	if err != nil {
		t.Fatalf("DiamondTicket failed: %v", err)
	}
	if ticket == nil {
		t.Fatal("Expected non-nil ticket")
	}
	if ticket.DecPart == nil {
		t.Fatal("Expected non-nil DecPart")
	}
	if ticket.DecPart.PACData == nil {
		t.Fatal("Expected non-nil PACData")
	}
}

func TestKerberoast(t *testing.T) {
	engine := NewKerberosEngine(nil)

	result, err := engine.Kerberoast("HTTP/web01.corp.local")
	if err != nil {
		t.Fatalf("Kerberoast failed: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.SPN != "HTTP/web01.corp.local" {
		t.Errorf("Expected SPN HTTP/web01.corp.local, got %s", result.SPN)
	}
	if result.Hash == "" {
		t.Error("Expected non-empty hash")
	}
}

func TestKerberoastEmptySPN(t *testing.T) {
	engine := NewKerberosEngine(nil)
	_, err := engine.Kerberoast("")
	if err == nil {
		t.Error("Expected error for empty SPN")
	}
}

func TestASREPRoast(t *testing.T) {
	engine := NewKerberosEngine(nil)

	result, err := engine.ASREPRoast("testuser")
	if err != nil {
		t.Fatalf("ASREPRoast failed: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.Username != "testuser" {
		t.Errorf("Expected username testuser, got %s", result.Username)
	}
	if result.Hash == "" {
		t.Error("Expected non-empty hash")
	}
}

func TestASREPRoastEmptyUser(t *testing.T) {
	engine := NewKerberosEngine(nil)
	_, err := engine.ASREPRoast("")
	if err == nil {
		t.Error("Expected error for empty user")
	}
}

func TestPassTheTicket(t *testing.T) {
	engine := NewKerberosEngine(nil)

	ticket, err := engine.GoldenTicket("CORP.LOCAL", "aad3b435b51404eeaad3b435b51404ee")
	if err != nil {
		t.Fatalf("GoldenTicket failed: %v", err)
	}

	ticketData, err := engine.forger.EncodeTicket(ticket)
	if err != nil {
		t.Fatalf("EncodeTicket failed: %v", err)
	}

	decoded, err := engine.forger.DecodeTicket(ticketData)
	if err != nil {
		t.Fatalf("DecodeTicket failed: %v", err)
	}
	if decoded.TicketVNO != 5 {
		t.Errorf("Expected ticket version 5, got %d", decoded.TicketVNO)
	}
	if decoded.Realm != "CORP.LOCAL" {
		t.Errorf("Expected realm CORP.LOCAL, got %s", decoded.Realm)
	}
}

func TestPassTheTicketEmptyData(t *testing.T) {
	engine := NewKerberosEngine(nil)
	err := engine.PassTheTicket(nil)
	if err == nil {
		t.Error("Expected error for nil data")
	}
}

func TestOverpassHash(t *testing.T) {
	engine := NewKerberosEngine(nil)

	ticket, err := engine.OverpassHash("aad3b435b51404eeaad3b435b51404ee")
	if err != nil {
		t.Fatalf("OverpassHash failed: %v", err)
	}
	if ticket == nil {
		t.Fatal("Expected non-nil ticket")
	}
}

func TestOverpassHashEmptyHash(t *testing.T) {
	engine := NewKerberosEngine(nil)
	_, err := engine.OverpassHash("")
	if err == nil {
		t.Error("Expected error for empty hash")
	}
}

func TestTicketForgerForgeTGT(t *testing.T) {
	forger := NewTicketForger(nil)

	ticket, err := forger.ForgeTGT("CORP.LOCAL", "Administrator", "aad3b435b51404eeaad3b435b51404ee", []int{512, 513})
	if err != nil {
		t.Fatalf("ForgeTGT failed: %v", err)
	}
	if ticket == nil {
		t.Fatal("Expected non-nil ticket")
	}
	if len(ticket.RawEncPart) == 0 {
		t.Error("Expected non-empty encrypted part")
	}
}

func TestTicketForgerForgeTGS(t *testing.T) {
	forger := NewTicketForger(nil)

	ticket, err := forger.ForgeTGS("CORP.LOCAL", "HTTP", "aad3b435b51404eeaad3b435b51404ee", []int{512, 513})
	if err != nil {
		t.Fatalf("ForgeTGS failed: %v", err)
	}
	if ticket == nil {
		t.Fatal("Expected non-nil ticket")
	}
}

func TestTicketForgerModifyPAC(t *testing.T) {
	forger := NewTicketForger(nil)

	ticket, err := forger.ForgeTGT("CORP.LOCAL", "Administrator", "aad3b435b51404eeaad3b435b51404ee", nil)
	if err != nil {
		t.Fatalf("ForgeTGT failed: %v", err)
	}

	err = forger.ModifyPAC(ticket, []string{"S-1-5-32-544"})
	if err != nil {
		t.Fatalf("ModifyPAC failed: %v", err)
	}

	if ticket.DecPart.PACData == nil {
		t.Error("Expected PAC data after modification")
	}
}

func TestTicketForgerEncodeDecode(t *testing.T) {
	forger := NewTicketForger(nil)

	ticket, err := forger.ForgeTGT("CORP.LOCAL", "Administrator", "aad3b435b51404eeaad3b435b51404ee", nil)
	if err != nil {
		t.Fatalf("ForgeTGT failed: %v", err)
	}

	encoded, err := forger.EncodeTicket(ticket)
	if err != nil {
		t.Fatalf("EncodeTicket failed: %v", err)
	}
	if len(encoded) == 0 {
		t.Error("Expected non-empty encoded ticket")
	}

	decoded, err := forger.DecodeTicket(encoded)
	if err != nil {
		t.Fatalf("DecodeTicket failed: %v", err)
	}
	if decoded.TicketVNO != 5 {
		t.Errorf("Expected ticket version 5, got %d", decoded.TicketVNO)
	}
	if decoded.Realm != "CORP.LOCAL" {
		t.Errorf("Expected realm CORP.LOCAL, got %s", decoded.Realm)
	}
}

func TestADCS(t *testing.T) {
	adcs := NewADCSEngine(nil)

	result, err := adcs.ESC1("User", "CORP-CA")
	if err != nil {
		t.Fatalf("ESC1 failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected ESC1 success")
	}
	if len(result.CertPEM) == 0 {
		t.Error("Expected non-empty certificate")
	}
	if len(result.KeyPEM) == 0 {
		t.Error("Expected non-empty key")
	}
}

func TestADCSESC1EmptyFields(t *testing.T) {
	adcs := NewADCSEngine(nil)

	_, err := adcs.ESC1("", "CORP-CA")
	if err == nil {
		t.Error("Expected error for empty template")
	}

	_, err = adcs.ESC1("User", "")
	if err == nil {
		t.Error("Expected error for empty CA")
	}
}

func TestADCSESC2(t *testing.T) {
	adcs := NewADCSEngine(nil)

	result, err := adcs.ESC2("User", "CORP-CA")
	if err != nil {
		t.Fatalf("ESC2 failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected ESC2 success")
	}
}

func TestADCSESC3(t *testing.T) {
	adcs := NewADCSEngine(nil)

	result, err := adcs.ESC3("EnrollmentAgent", "CORP-CA")
	if err != nil {
		t.Fatalf("ESC3 failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected ESC3 success")
	}
}

func TestADCSESC6(t *testing.T) {
	adcs := NewADCSEngine(nil)

	result, err := adcs.ESC6("CORP-CA")
	if err != nil {
		t.Fatalf("ESC6 failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected ESC6 success")
	}
}

func TestADCSESC6EmptyCA(t *testing.T) {
	adcs := NewADCSEngine(nil)
	_, err := adcs.ESC6("")
	if err == nil {
		t.Error("Expected error for empty CA")
	}
}

func TestADCSESC8(t *testing.T) {
	adcs := NewADCSEngine(nil)

	result, err := adcs.ESC8("CORP-CA")
	if err != nil {
		t.Fatalf("ESC8 failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected ESC8 success")
	}
}

func TestADCSEnumerateTemplates(t *testing.T) {
	adcs := NewADCSEngine(nil)

	templates, err := adcs.EnumerateTemplates()
	if err != nil {
		t.Fatalf("EnumerateTemplates failed: %v", err)
	}
	if len(templates) == 0 {
		t.Error("Expected at least one template")
	}
}

func TestADCSEnumerateCAs(t *testing.T) {
	adcs := NewADCSEngine(nil)

	cas, err := adcs.EnumerateCAs()
	if err != nil {
		t.Fatalf("EnumerateCAs failed: %v", err)
	}
	if len(cas) == 0 {
		t.Error("Expected at least one CA")
	}
}

func TestADReconEnumDomain(t *testing.T) {
	recon := NewADRecon(nil)

	info, err := recon.EnumDomain()
	if err != nil {
		t.Fatalf("EnumDomain failed: %v", err)
	}
	if info.Name != "CORP.LOCAL" {
		t.Errorf("Expected domain name CORP.LOCAL, got %s", info.Name)
	}
}

func TestADReconEnumUsers(t *testing.T) {
	recon := NewADRecon(nil)

	users, err := recon.EnumUsers()
	if err != nil {
		t.Fatalf("EnumUsers failed: %v", err)
	}
	if len(users) == 0 {
		t.Error("Expected at least one user")
	}
}

func TestADReconEnumGroups(t *testing.T) {
	recon := NewADRecon(nil)

	groups, err := recon.EnumGroups()
	if err != nil {
		t.Fatalf("EnumGroups failed: %v", err)
	}
	if len(groups) == 0 {
		t.Error("Expected at least one group")
	}
}

func TestADReconEnumSPNs(t *testing.T) {
	recon := NewADRecon(nil)

	spns, err := recon.EnumSPNs()
	if err != nil {
		t.Fatalf("EnumSPNs failed: %v", err)
	}
	if len(spns) == 0 {
		t.Error("Expected at least one SPN")
	}
}

func TestADReconEnumGPO(t *testing.T) {
	recon := NewADRecon(nil)

	gpos, err := recon.EnumGPO()
	if err != nil {
		t.Fatalf("EnumGPO failed: %v", err)
	}
	if len(gpos) == 0 {
		t.Error("Expected at least one GPO")
	}
}

func TestADReconDCSync(t *testing.T) {
	recon := NewADRecon(nil)

	result, err := recon.DCSync("dc01.corp.local")
	if err != nil {
		t.Fatalf("DCSync failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected DCSync success")
	}
	if result.NTLMHash == "" {
		t.Error("Expected non-empty NTLM hash")
	}
	if result.KRBTGT == "" {
		t.Error("Expected non-empty KRBTGT hash")
	}
}

func TestTicketFlags(t *testing.T) {
	var flags TicketFlags

	flags.SetFlag(TicketFlagInitial)
	if !flags.HasFlag(TicketFlagInitial) {
		t.Error("Expected TicketFlagInitial to be set")
	}

	flags.SetFlag(TicketFlagForwardable)
	if !flags.HasFlag(TicketFlagForwardable) {
		t.Error("Expected TicketFlagForwardable to be set")
	}

	flags.ClearFlag(TicketFlagInitial)
	if flags.HasFlag(TicketFlagInitial) {
		t.Error("Expected TicketFlagInitial to be cleared")
	}

	if !flags.HasFlag(TicketFlagForwardable) {
		t.Error("Expected TicketFlagForwardable to still be set")
	}
}

func TestTicketValidate(t *testing.T) {
	forger := NewTicketForger(nil)

	ticket, err := forger.ForgeTGT("CORP.LOCAL", "Administrator", "aad3b435b51404eeaad3b435b51404ee", nil)
	if err != nil {
		t.Fatalf("ForgeTGT failed: %v", err)
	}

	if err := ticket.Validate(); err != nil {
		t.Fatalf("Ticket validation failed: %v", err)
	}
}

func TestHexToBytes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"41424344", "ABCD", false},
		{"aabbccdd", "\xaa\xbb\xcc\xdd", false},
		{"AABBCCDD", "\xaa\xbb\xcc\xdd", false},
		{"123", "", true},
		{"", "", false},
	}

	for _, tt := range tests {
		result, err := hexToBytes(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("hexToBytes(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if string(result) != tt.expected {
			t.Errorf("hexToBytes(%s) = %x, want %x", tt.input, result, tt.expected)
		}
	}
}

func TestKerberosEngineConfig(t *testing.T) {
	config := &KerberosConfig{
		Domain:       "TEST.LOCAL",
		DomainController: "dc01.test.local",
		KDCPort:      88,
		Realm:        "TEST.LOCAL",
		Timeout:      60 * time.Second,
		EncType:      EncAES256,
	}

	engine := NewKerberosEngine(config)
	if engine.config.Domain != "TEST.LOCAL" {
		t.Errorf("Expected domain TEST.LOCAL, got %s", engine.config.Domain)
	}
	if engine.config.EncType != EncAES256 {
		t.Errorf("Expected AES256 encryption, got %d", engine.config.EncType)
	}
}
