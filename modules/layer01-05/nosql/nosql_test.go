package nosql

import (
	"strings"
	"testing"
	"time"
)

func TestNewNoSQLEngine(t *testing.T) {
	config := DefaultNoSQLConfig()
	engine := NewNoSQLEngine(config)

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

func TestNewNoSQLEngineWithNilConfig(t *testing.T) {
	engine := NewNoSQLEngine(nil)

	if engine == nil {
		t.Fatal("engine should not be nil")
	}
	if engine.config == nil {
		t.Fatal("config should not be nil")
	}
	if len(engine.config.DBTypes) != 5 {
		t.Fatalf("expected 5 db types, got %d", len(engine.config.DBTypes))
	}
}

func TestDefaultNoSQLConfig(t *testing.T) {
	config := DefaultNoSQLConfig()

	if config.Port != 27017 {
		t.Errorf("expected port 27017, got %d", config.Port)
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", config.Timeout)
	}
	if config.MaxRetries != 3 {
		t.Errorf("expected max retries 3, got %d", config.MaxRetries)
	}
	if config.Database != "test" {
		t.Errorf("expected database 'test', got %s", config.Database)
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

func TestScanResultSummary(t *testing.T) {
	result := &ScanResult{
		Target:    "localhost",
		DBType:    NoSQLDBMongoDB,
		Vulnerable: true,
		Version:   "4.4.0",
		Injections: []InjectionPoint{
			{ID: "test"},
		},
	}

	summary := result.Summary()
	if summary == "" {
		t.Error("summary should not be empty")
	}
}

func TestScanResultAddInjection(t *testing.T) {
	result := &ScanResult{
		Target: "localhost",
	}

	inj := InjectionPoint{
		ID:       "test",
		Severity: SeverityHigh,
	}

	result.AddInjection(inj)

	if len(result.Injections) != 1 {
		t.Errorf("expected 1 injection, got %d", len(result.Injections))
	}
	if !result.Vulnerable {
		t.Error("result should be vulnerable with high severity injection")
	}
}

func TestMongoDBTestConnection(t *testing.T) {
	config := DefaultNoSQLConfig()
	client := NewHTTPClient(config)
	m := NewMongoDBScanner(config, client)

	result := m.TestConnection("http://localhost:27017")
	if result {
		t.Log("MongoDB connection test passed")
	}
}

func TestESSTestConnection(t *testing.T) {
	config := DefaultNoSQLConfig()
	client := NewHTTPClient(config)
	es := NewESScanner(config, client)

	result := es.TestConnection("http://localhost:9200")
	if result {
		t.Log("Elasticsearch connection test passed")
	}
}

func TestCouchDBTestConnection(t *testing.T) {
	config := DefaultNoSQLConfig()
	client := NewHTTPClient(config)
	couch := NewCouchDBScanner(config, client)

	result := couch.TestConnection("http://localhost:5984")
	if result {
		t.Log("CouchDB connection test passed")
	}
}

func TestRedisTestConnection(t *testing.T) {
	config := DefaultNoSQLConfig()
	client := NewHTTPClient(config)
	redis := NewRedisScanner(config, client)

	result := redis.TestConnection("http://localhost:6379")
	if result {
		t.Log("Redis connection test passed")
	}
}

func TestCassandraTestConnection(t *testing.T) {
	config := DefaultNoSQLConfig()
	client := NewHTTPClient(config)
	cass := NewCassandraScanner(config, client)

	result := cass.TestConnection("http://localhost:9042")
	if result {
		t.Log("Cassandra connection test passed")
	}
}

func TestHTTPClientGet(t *testing.T) {
	config := DefaultNoSQLConfig()
	client := NewHTTPClient(config)

	resp, body, err := client.Get("http://httpbin.org/get", nil)
	if err != nil {
		t.Skipf("skipping HTTP test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if len(body) == 0 {
		t.Error("body should not be empty")
	}
}

func TestHTTPClientPost(t *testing.T) {
	config := DefaultNoSQLConfig()
	client := NewHTTPClient(config)

	resp, body, err := client.Post("http://httpbin.org/post",
		strings.NewReader(`{"test":"data"}`), map[string]string{
			"Content-Type": "application/json",
		})
	if err != nil {
		t.Skipf("skipping HTTP test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if len(body) == 0 {
		t.Error("body should not be empty")
	}
}

func TestNoSQLDBTypeConstants(t *testing.T) {
	types := []NoSQLDBType{
		NoSQLDBMongoDB,
		NoSQLDBElasticsearch,
		NoSQLDBCouchDB,
		NoSQLDBRedis,
		NoSQLDBCassandra,
	}

	if len(types) != 5 {
		t.Errorf("expected 5 db types, got %d", len(types))
	}

	for _, dbType := range types {
		if dbType == "" {
			t.Error("db type should not be empty")
		}
	}
}

func TestInjectionTechniqueConstants(t *testing.T) {
	techniques := []InjectionTechnique{
		TechniqueAuthBypass,
		TechniqueBooleanBlind,
		TechniqueTimeBased,
		TechniqueJSInject,
		TechniqueLookupExfil,
		TechniqueQueryInject,
		TechniqueAggregation,
		TechniqueScriptInject,
		TechniqueCommandInject,
		TechniqueKeyDump,
		TechniqueCQLInject,
	}

	if len(techniques) != 11 {
		t.Errorf("expected 11 techniques, got %d", len(techniques))
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
