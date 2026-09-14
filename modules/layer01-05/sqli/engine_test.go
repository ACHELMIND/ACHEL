package sqli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestBooleanBlindDetector(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		if strings.Contains(param, "' OR '1'='1") || strings.Contains(param, "' OR 1=1--") ||
			strings.Contains(param, "1 OR 1=1") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "<html><body>Results: user1, user2, user3, admin, test</body></html>")
		} else if strings.Contains(param, "' OR '1'='2") || strings.Contains(param, "' OR 1=2--") ||
			strings.Contains(param, "1 OR 1=2") {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "<html><body>No results found</body></html>")
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "<html><body>Default page content here</body></html>")
		}
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	engine := NewSQLiEngine(&SQLiConfig{
		Timeout:    5 * time.Second,
		Techniques: []InjectionType{InjectionBooleanBlind},
	})
	defer engine.Close()

	detector := NewBooleanBlindDetector(engine)
	result, err := detector.Detect(server.URL, []string{"id"})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.Found {
		t.Error("Expected injection to be found")
	}
	if result.Type != InjectionBooleanBlind {
		t.Errorf("Expected type %s, got %s", InjectionBooleanBlind, result.Type)
	}
	if result.Confidence < 0.5 {
		t.Errorf("Expected confidence > 0.5, got %f", result.Confidence)
	}
}

func TestTimeBasedDetector(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		if strings.Contains(param, "SLEEP") || strings.Contains(param, "pg_sleep") ||
			strings.Contains(param, "WAITFOR") {
			time.Sleep(3 * time.Second)
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "<html><body>Sleep executed</body></html>")
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "<html><body>Normal response</body></html>")
		}
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	engine := NewSQLiEngine(&SQLiConfig{
		Timeout:    10 * time.Second,
		Techniques: []InjectionType{InjectionTimeBased},
	})
	defer engine.Close()

	detector := NewTimeBasedDetector(engine)
	result, err := detector.Detect(server.URL, []string{"id"})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.Found {
		t.Error("Expected injection to be found")
	}
	if result.Type != InjectionTimeBased {
		t.Errorf("Expected type %s, got %s", InjectionTimeBased, result.Type)
	}
}

func TestWAFBypass(t *testing.T) {
	engine := NewWAFBypassEngine()

	if engine.Count() != 12 {
		t.Errorf("Expected 12 techniques, got %d", engine.Count())
	}

	payload := "' OR '1'='1"

	bypassed := engine.Bypass(payload)
	if bypassed == payload {
		t.Error("Expected bypass to modify payload")
	}

	all := engine.BypassAll(payload)
	if len(all) < 10 {
		t.Errorf("Expected at least 10 unique bypasses, got %d", len(all))
	}

	names := engine.GetTechniqueNames()
	if len(names) != 12 {
		t.Errorf("Expected 12 technique names, got %d", len(names))
	}

	expectedNames := map[string]bool{
		"hex_encoding":        true,
		"char_function":       true,
		"unicode_encoding":    true,
		"double_url_encoding": true,
		"case_variation":      true,
		"comment_insertion":   true,
		"whitespace_variants": true,
		"json_body":           true,
		"graphql_param":       true,
		"xml_param":           true,
		"multipart_form":      true,
		"ua_rotation":         true,
	}

	for _, name := range names {
		if !expectedNames[name] {
			t.Errorf("Unexpected technique name: %s", name)
		}
	}
}

func TestScheduler(t *testing.T) {
	engine := NewSQLiEngine(DefaultConfig())
	defer engine.Close()

	scheduler := NewScheduler(engine)

	techniques := scheduler.ScheduleTechniques("http://example.com/test?id=1")

	if len(techniques) == 0 {
		t.Error("Expected at least one technique")
	}

	priority := 0
	for _, tech := range techniques {
		if tech.Priority < priority && priority != 0 {
			t.Errorf("Techniques not sorted by priority: %d < %d", tech.Priority, priority)
		}
		priority = tech.Priority
	}

	if techniques[0].Status != TechniqueStatusPending {
		t.Errorf("Expected first technique to be pending, got %s", techniques[0].Status)
	}

	queue := scheduler.GetQueue()
	if len(queue) != len(techniques) {
		t.Errorf("Queue length mismatch: %d != %d", len(queue), len(techniques))
	}

	scheduler.ClearQueue()
	queue = scheduler.GetQueue()
	if len(queue) != 0 {
		t.Errorf("Expected empty queue after clear, got %d", len(queue))
	}
}

func TestPayloadGeneration(t *testing.T) {
	tests := []struct {
		name   string
		dbms   DBMSType
		method string
	}{
		{"MySQL Boolean", DBMSMySQL, "boolean"},
		{"MySQL Time", DBMSMySQL, "time"},
		{"MySQL Error", DBMSMySQL, "error"},
		{"MySQL Union", DBMSMySQL, "union"},
		{"MySQL Version", DBMSMySQL, "version"},
		{"MySQL Database", DBMSMySQL, "database"},
		{"MySQL User", DBMSMySQL, "user"},
		{"PostgreSQL Boolean", DBMSPostgres, "boolean"},
		{"PostgreSQL Time", DBMSPostgres, "time"},
		{"MSSQL Boolean", DBMSMSSQL, "boolean"},
		{"MSSQL Time", DBMSMSSQL, "time"},
		{"Oracle Boolean", DBMSOracle, "boolean"},
		{"SQLite Boolean", DBMSSQLite, "boolean"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewPayloadGenerator(tt.dbms)

			switch tt.method {
			case "boolean":
				trueP := gen.BooleanTrue()
				falseP := gen.BooleanFalse()
				if trueP == "" || falseP == "" {
					t.Error("Empty boolean payloads")
				}
				if trueP == falseP {
					t.Error("True and false payloads are identical")
				}
			case "time":
				p := gen.TimeBasedDelay(5)
				if p == "" {
					t.Error("Empty time-based payload")
				}
			case "error":
				p := gen.ErrorExtractValue("version()")
				if p == "" {
					t.Error("Empty error-based payload")
				}
			case "union":
				gen.SetColumns(5)
				p := gen.UnionSelect(5)
				if p == "" {
					t.Error("Empty union payload")
				}
				if !strings.Contains(p, "UNION") {
					t.Error("Union payload missing UNION keyword")
				}
			case "version":
				p := gen.Version()
				if p == "" {
					t.Error("Empty version payload")
				}
			case "database":
				p := gen.Database()
				if p == "" {
					t.Error("Empty database payload")
				}
			case "user":
				p := gen.User()
				if p == "" {
					t.Error("Empty user payload")
				}
			}
		})
	}
}

func TestSQLiEngineScan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		if strings.Contains(param, "'1'='1") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "<html><body>Results found</body></html>")
		} else if strings.Contains(param, "SLEEP") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "<html><body>Sleep executed</body></html>")
		} else if strings.Contains(param, "UNION") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "<html><body>MySQL 5.7.42</body></html>")
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "<html><body>Default</body></html>")
		}
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	engine := NewSQLiEngine(&SQLiConfig{
		Timeout:    10 * time.Second,
		Techniques: []InjectionType{InjectionBooleanBlind, InjectionTimeBased},
		Params:     []string{"id"},
	})
	defer engine.Close()

	result, err := engine.Scan(server.URL + "?id=1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Target == "" {
		t.Error("Expected target to be set")
	}
	if result.Duration == 0 {
		t.Error("Expected duration to be non-zero")
	}
	if result.EndTime.Before(result.StartTime) {
		t.Error("Expected end time to be after start time")
	}
}

func TestExploit(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		if strings.Contains(param, "version()") {
			fmt.Fprintf(w, "MySQL 5.7.42")
		} else if strings.Contains(param, "database()") || strings.Contains(param, "current_database()") {
			fmt.Fprintf(w, "testdb")
		} else if strings.Contains(param, "user()") || strings.Contains(param, "current_user") {
			fmt.Fprintf(w, "root@localhost")
		} else {
			fmt.Fprintf(w, "Default")
		}
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	engine := NewSQLiEngine(&SQLiConfig{
		Timeout: 10 * time.Second,
	})
	defer engine.Close()

	pt := &InjectionPoint{
		URL:           server.URL,
		Parameter:     "id",
		Location:      ParamQuery,
		InjectionType: InjectionBooleanBlind,
		DBMS:          DBMSMySQL,
		Confidence:    0.9,
		Severity:      SeverityHigh,
	}

	result, err := engine.Exploit(pt)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.Success {
		t.Error("Expected exploitation to succeed")
	}
	if result.DBMS != DBMSMySQL {
		t.Errorf("Expected DBMS %s, got %s", DBMSMySQL, result.DBMS)
	}
}

func TestRegexpExtractValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"~MySQL 5.7.42~", "MySQL 5.7.42"},
		{"~testdb~", "testdb"},
		{"prefix~value~suffix", "value"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			re := regexp.MustCompile("~(.+?)~")
			matches := re.FindStringSubmatch(tt.input)
			if len(matches) > 1 {
				if matches[1] != tt.expected {
					t.Errorf("Expected %s, got %s", tt.expected, matches[1])
				}
			}
		})
	}
}
