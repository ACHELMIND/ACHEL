package dbpost

import (
	"fmt"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type DBPostEngine struct {
	config     *DBPostConfig
	httpClient *HTTPClient
	log        *logger.Logger
}

func NewDBPostEngine(config *DBPostConfig) *DBPostEngine {
	if config == nil {
		config = DefaultDBPostConfig()
	}

	return &DBPostEngine{
		config:     config,
		httpClient: NewHTTPClient(config),
		log:        logger.New("dbpost-engine", logger.LevelInfo),
	}
}

func (e *DBPostEngine) Exploit(dbms string, creds *DBCreds) (*PostExploitResult, error) {
	if creds == nil {
		return nil, fmt.Errorf("credentials are required")
	}

	e.log.Info("Starting database post-exploitation for %s", dbms)

	result := &PostExploitResult{
		DBMS:      DBMS(dbms),
		Timestamp: time.Now(),
	}

	switch DBMS(dbms) {
	case DBMSOracle:
		return e.exploitOracle(creds, result)
	case DBMSMySQL:
		return e.exploitMySQL(creds, result)
	case DBMSPostgres:
		return e.exploitPostgreSQL(creds, result)
	case DBMSMSSQL:
		return e.exploitMSSQL(creds, result)
	default:
		return nil, fmt.Errorf("unsupported DBMS: %s", dbms)
	}
}

func (e *DBPostEngine) ExploitWithTechnique(dbms string, creds *DBCreds, technique ExploitTechnique) (*PostExploitResult, error) {
	if creds == nil {
		return nil, fmt.Errorf("credentials are required")
	}

	e.log.Info("Executing %s technique on %s", technique, dbms)

	result := &PostExploitResult{
		DBMS:      DBMS(dbms),
		Technique: technique,
		Timestamp: time.Now(),
	}

	switch DBMS(dbms) {
	case DBMSOracle:
		oracle := NewOracleExploit(e.config, e.httpClient)
		switch technique {
		case TechniqueJavaObject:
			return oracle.JavaObjectInject(creds, result)
		case TechniqueKhuntCmd:
			return oracle.KhuntCmd(creds, result)
		case TechniqueKhuntHash:
			return oracle.KhuntHash(creds, result)
		case TechniqueRegistryDump:
			return oracle.RegistryDump(creds, result)
		default:
			return nil, fmt.Errorf("unsupported Oracle technique: %s", technique)
		}

	case DBMSMySQL:
		mysql := NewMySQLExploit(e.config, e.httpClient)
		switch technique {
		case TechniqueUDFInstall:
			return mysql.UDFInstall(creds, result)
		case TechniqueUserExtract:
			return mysql.UserExtract(creds, result)
		case TechniqueFSAccess:
			return mysql.FSAccess(creds, result)
		default:
			return nil, fmt.Errorf("unsupported MySQL technique: %s", technique)
		}

	case DBMSPostgres:
		pg := NewPostgresExploit(e.config, e.httpClient)
		switch technique {
		case TechniqueCopyProgram:
			return pg.CopyProgram(creds, result)
		case TechniquePGShadow:
			return pg.PGShadow(creds, result)
		case TechniqueFSAccess:
			return pg.FSAccess(creds, result)
		default:
			return nil, fmt.Errorf("unsupported PostgreSQL technique: %s", technique)
		}

	case DBMSMSSQL:
		mssql := NewMSSQLExploit(e.config, e.httpClient)
		switch technique {
		case TechniqueXPCmdShell:
			return mssql.XPCmdShell(creds, result)
		case TechniqueCLRAssembly:
			return mssql.CLRAssembly(creds, result)
		case TechniqueSQLLogins:
			return mssql.SQLLogins(creds, result)
		default:
			return nil, fmt.Errorf("unsupported MSSQL technique: %s", technique)
		}

	default:
		return nil, fmt.Errorf("unsupported DBMS: %s", dbms)
	}
}

func (e *DBPostEngine) exploitOracle(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	oracle := NewOracleExploit(e.config, e.httpClient)

	e.log.Debug("Trying Java Object injection on Oracle")
	if r, err := oracle.JavaObjectInject(creds, result); err == nil && r.Success {
		return r, nil
	}

	e.log.Debug("Trying KhuntCmd on Oracle")
	if r, err := oracle.KhuntCmd(creds, result); err == nil && r.Success {
		return r, nil
	}

	e.log.Debug("Trying KhuntHash on Oracle")
	if r, err := oracle.KhuntHash(creds, result); err == nil && r.Success {
		return r, nil
	}

	e.log.Debug("Trying RegistryDump on Oracle")
	if r, err := oracle.RegistryDump(creds, result); err == nil && r.Success {
		return r, nil
	}

	result.Error = "all Oracle exploitation techniques failed"
	return result, nil
}

func (e *DBPostEngine) exploitMySQL(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	mysql := NewMySQLExploit(e.config, e.httpClient)

	e.log.Debug("Trying UDF install on MySQL")
	if r, err := mysql.UDFInstall(creds, result); err == nil && r.Success {
		return r, nil
	}

	e.log.Debug("Trying user extraction on MySQL")
	if r, err := mysql.UserExtract(creds, result); err == nil && r.Success {
		return r, nil
	}

	e.log.Debug("Trying filesystem access on MySQL")
	if r, err := mysql.FSAccess(creds, result); err == nil && r.Success {
		return r, nil
	}

	result.Error = "all MySQL exploitation techniques failed"
	return result, nil
}

func (e *DBPostEngine) exploitPostgreSQL(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	pg := NewPostgresExploit(e.config, e.httpClient)

	e.log.Debug("Trying COPY PROGRAM on PostgreSQL")
	if r, err := pg.CopyProgram(creds, result); err == nil && r.Success {
		return r, nil
	}

	e.log.Debug("Trying pg_shadow extraction on PostgreSQL")
	if r, err := pg.PGShadow(creds, result); err == nil && r.Success {
		return r, nil
	}

	e.log.Debug("Trying filesystem access on PostgreSQL")
	if r, err := pg.FSAccess(creds, result); err == nil && r.Success {
		return r, nil
	}

	result.Error = "all PostgreSQL exploitation techniques failed"
	return result, nil
}

func (e *DBPostEngine) exploitMSSQL(creds *DBCreds, result *PostExploitResult) (*PostExploitResult, error) {
	mssql := NewMSSQLExploit(e.config, e.httpClient)

	e.log.Debug("Trying xp_cmdshell on MSSQL")
	if r, err := mssql.XPCmdShell(creds, result); err == nil && r.Success {
		return r, nil
	}

	e.log.Debug("Trying CLR assembly on MSSQL")
	if r, err := mssql.CLRAssembly(creds, result); err == nil && r.Success {
		return r, nil
	}

	e.log.Debug("Trying SQL logins enumeration on MSSQL")
	if r, err := mssql.SQLLogins(creds, result); err == nil && r.Success {
		return r, nil
	}

	result.Error = "all MSSQL exploitation techniques failed"
	return result, nil
}
