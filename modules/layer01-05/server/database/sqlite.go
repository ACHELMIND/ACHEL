package database

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	mu     sync.RWMutex
	db     *sql.DB
	path   string
}

type AgentRecord struct {
	ID        string
	Hostname  string
	IP        string
	OS        string
	Arch      string
	LastSeen  time.Time
	FirstSeen time.Time
}

type TaskRecord struct {
	ID        string
	AgentID   string
	Type      string
	Payload   string
	Status    string
	Result    string
	CreatedAt time.Time
	StartedAt time.Time
	EndedAt   time.Time
}

type ResultRecord struct {
	ID        string
	TaskID    string
	AgentID   string
	Success   bool
	Output    string
	Error     string
	Timestamp time.Time
}

func NewDatabase(path string) (*Database, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	d := &Database{
		db:   db,
		path: path,
	}

	if err := d.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return d, nil
}

func (d *Database) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS agents (
			id TEXT PRIMARY KEY,
			hostname TEXT,
			ip TEXT,
			os TEXT,
			arch TEXT,
			last_seen DATETIME,
			first_seen DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS tasks (
			id TEXT PRIMARY KEY,
			agent_id TEXT,
			type TEXT,
			payload TEXT,
			status TEXT,
			result TEXT,
			created_at DATETIME,
			started_at DATETIME,
			ended_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS results (
			id TEXT PRIMARY KEY,
			task_id TEXT,
			agent_id TEXT,
			success BOOLEAN,
			output TEXT,
			error TEXT,
			timestamp DATETIME
		)`,
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return err
		}
	}

	return nil
}

func (d *Database) SaveAgent(agent *AgentRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		`INSERT OR REPLACE INTO agents (id, hostname, ip, os, arch, last_seen, first_seen) 
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		agent.ID, agent.Hostname, agent.IP, agent.OS, agent.Arch, agent.LastSeen, agent.FirstSeen,
	)
	return err
}

func (d *Database) GetAgent(id string) (*AgentRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	agent := &AgentRecord{}
	err := d.db.QueryRow(
		`SELECT id, hostname, ip, os, arch, last_seen, first_seen FROM agents WHERE id = ?`, id,
	).Scan(&agent.ID, &agent.Hostname, &agent.IP, &agent.OS, &agent.Arch, &agent.LastSeen, &agent.FirstSeen)
	if err != nil {
		return nil, err
	}
	return agent, nil
}

func (d *Database) GetAllAgents() ([]*AgentRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`SELECT id, hostname, ip, os, arch, last_seen, first_seen FROM agents`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []*AgentRecord
	for rows.Next() {
		agent := &AgentRecord{}
		if err := rows.Scan(&agent.ID, &agent.Hostname, &agent.IP, &agent.OS, &agent.Arch, &agent.LastSeen, &agent.FirstSeen); err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}

	return agents, nil
}

func (d *Database) SaveTask(task *TaskRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		`INSERT OR REPLACE INTO tasks (id, agent_id, type, payload, status, result, created_at, started_at, ended_at) 
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		task.ID, task.AgentID, task.Type, task.Payload, task.Status, task.Result, task.CreatedAt, task.StartedAt, task.EndedAt,
	)
	return err
}

func (d *Database) GetTask(id string) (*TaskRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	task := &TaskRecord{}
	err := d.db.QueryRow(
		`SELECT id, agent_id, type, payload, status, result, created_at, started_at, ended_at FROM tasks WHERE id = ?`, id,
	).Scan(&task.ID, &task.AgentID, &task.Type, &task.Payload, &task.Status, &task.Result, &task.CreatedAt, &task.StartedAt, &task.EndedAt)
	if err != nil {
		return nil, err
	}
	return task, nil
}

func (d *Database) GetPendingTasks(agentID string) ([]*TaskRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(
		`SELECT id, agent_id, type, payload, status, result, created_at, started_at, ended_at 
		 FROM tasks WHERE agent_id = ? AND status = 'pending'`, agentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*TaskRecord
	for rows.Next() {
		task := &TaskRecord{}
		if err := rows.Scan(&task.ID, &task.AgentID, &task.Type, &task.Payload, &task.Status, &task.Result, &task.CreatedAt, &task.StartedAt, &task.EndedAt); err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}

	return tasks, nil
}

func (d *Database) SaveResult(result *ResultRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		`INSERT OR REPLACE INTO results (id, task_id, agent_id, success, output, error, timestamp) 
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		result.ID, result.TaskID, result.AgentID, result.Success, result.Output, result.Error, result.Timestamp,
	)
	return err
}

func (d *Database) Close() error {
	return d.db.Close()
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
