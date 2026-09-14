package dbpost

import (
	"testing"
	"time"
)

func TestNewDBPostEngine(t *testing.T) {
	config := DefaultDBPostConfig()
	engine := NewDBPostEngine(config)

	if engine == nil {
		t.Fatal("engine should not be nil")
	}
	if engine.config == nil {
		t.Fatal("config should not be nil")
	}
	if engine.httpClient == nil {
		t.Fatal("httpClient should not be nil")
	}
	if engine.log == nil {
		t.Fatal("log should not be nil")
	}
}

func TestNewDBPostEngineWithNilConfig(t *testing.T) {
	engine := NewDBPostEngine(nil)

	if engine == nil {
		t.Fatal("engine should not be nil")
	}
	if engine.config == nil {
		t.Fatal("config should not be nil")
	}
	if engine.config.Port != 1521 {
		t.Errorf("expected port 1521, got %d", engine.config.Port)
	}
}

func TestDefaultDBPostConfig(t *testing.T) {
	config := DefaultDBPostConfig()

	if config.Port != 1521 {
		t.Errorf("expected port 1521, got %d", config.Port)
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", config.Timeout)
	}
	if config.MaxRetries != 3 {
		t.Errorf("expected max retries 3, got %d", config.MaxRetries)
	}
	if config.ServiceName != "ORCL" {
		t.Errorf("expected service name ORCL, got %s", config.ServiceName)
	}
}

func TestBuildURL(t *testing.T) {
	tests := []struct {
		target string
		path   string
		port   int
		want   string
	}{
		{"http://example.com", "/test", 0, "http://example.com/test"},
		{"example.com", "/test", 8080, "http://example.com:8080/test"},
		{"http://example.com", "/test", 80, "http://example.com/test"},
		{"http://example.com", "/test", 443, "http://example.com/test"},
	}

	for _, tt := range tests {
		got := BuildURL(tt.target, tt.path, tt.port)
		if got != tt.want {
			t.Errorf("BuildURL(%s, %s, %d) = %s, want %s", tt.target, tt.path, tt.port, got, tt.want)
		}
	}
}

func TestGenerateID(t *testing.T) {
	id1 := GenerateID()
	id2 := GenerateID()

	if id1 == "" {
		t.Error("ID should not be empty")
	}
	if id2 == "" {
		t.Error("ID should not be empty")
	}
}

func TestDBMSConstants(t *testing.T) {
	dbmsList := []DBMS{
		DBMSOracle,
		DBMSMySQL,
		DBMSPostgres,
		DBMSMSSQL,
	}

	if len(dbmsList) != 4 {
		t.Errorf("expected 4 dbms types, got %d", len(dbmsList))
	}

	for _, dbms := range dbmsList {
		if dbms == "" {
			t.Error("dbms should not be empty")
		}
	}
}

func TestExploitTechniqueConstants(t *testing.T) {
	techniques := []ExploitTechnique{
		TechniqueJavaObject,
		TechniqueKhuntCmd,
		TechniqueKhuntHash,
		TechniqueRegistryDump,
		TechniqueUDFInstall,
		TechniqueUserExtract,
		TechniqueFSAccess,
		TechniqueCopyProgram,
		TechniquePGShadow,
		TechniqueXPCmdShell,
		TechniqueCLRAssembly,
		TechniqueSQLLogins,
	}

	if len(techniques) != 12 {
		t.Errorf("expected 12 techniques, got %d", len(techniques))
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		s    Severity
		want string
	}{
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		got := tt.s.String()
		if got != tt.want {
			t.Errorf("Severity(%d).String() = %s, want %s", tt.s, got, tt.want)
		}
	}
}

func TestExploitResultSuccess(t *testing.T) {
	result := &PostExploitResult{
		Success: true,
		DBMS:    DBMSMySQL,
		Data: map[string]interface{}{
			"method": "test",
		},
	}

	if !result.Success {
		t.Error("expected success to be true")
	}
	if result.DBMS != DBMSMySQL {
		t.Errorf("expected DBMS mysql, got %s", result.DBMS)
	}
}

func TestDBCredsStructure(t *testing.T) {
	creds := &DBCreds{
		Username:    "admin",
		Password:    "password",
		Database:    "test",
		Host:        "localhost",
		Port:        3306,
		IsAdmin:     true,
		Role:        "DBA",
	}

	if creds.Username != "admin" {
		t.Errorf("expected username admin, got %s", creds.Username)
	}
	if creds.Port != 3306 {
		t.Errorf("expected port 3306, got %d", creds.Port)
	}
	if !creds.IsAdmin {
		t.Error("expected is_admin to be true")
	}
}

func TestHTTPClientCreation(t *testing.T) {
	config := DefaultDBPostConfig()
	client := NewHTTPClient(config)

	if client == nil {
		t.Fatal("client should not be nil")
	}
	if client.client == nil {
		t.Fatal("http client should not be nil")
	}
	if client.config == nil {
		t.Fatal("config should not be nil")
	}
}

func TestOracleExploitCreation(t *testing.T) {
	config := DefaultDBPostConfig()
	client := NewHTTPClient(config)
	oracle := NewOracleExploit(config, client)

	if oracle == nil {
		t.Fatal("oracle exploit should not be nil")
	}
}

func TestMySQLExploitCreation(t *testing.T) {
	config := DefaultDBPostConfig()
	client := NewHTTPClient(config)
	mysql := NewMySQLExploit(config, client)

	if mysql == nil {
		t.Fatal("mysql exploit should not be nil")
	}
}

func TestPostgresExploitCreation(t *testing.T) {
	config := DefaultDBPostConfig()
	client := NewHTTPClient(config)
	pg := NewPostgresExploit(config, client)

	if pg == nil {
		t.Fatal("postgres exploit should not be nil")
	}
}

func TestMSSQLExploitCreation(t *testing.T) {
	config := DefaultDBPostConfig()
	client := NewHTTPClient(config)
	mssql := NewMSSQLExploit(config, client)

	if mssql == nil {
		t.Fatal("mssql exploit should not be nil")
	}
}

func TestDBPostEngineExploitNilCreds(t *testing.T) {
	config := DefaultDBPostConfig()
	engine := NewDBPostEngine(config)

	_, err := engine.Exploit("mysql", nil)
	if err == nil {
		t.Error("expected error for nil credentials")
	}
}

func TestDBPostEngineExploitUnsupportedDBMS(t *testing.T) {
	config := DefaultDBPostConfig()
	engine := NewDBPostEngine(config)

	creds := &DBCreds{
		Username: "admin",
		Password: "password",
	}

	_, err := engine.Exploit("unsupported", creds)
	if err == nil {
		t.Error("expected error for unsupported DBMS")
	}
}
