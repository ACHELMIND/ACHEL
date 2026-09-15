package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type TaskQueue struct {
	mu       sync.RWMutex
	tasks    map[string]*QueuedTask
	priority []string
	running  bool
}

type QueuedTask struct {
	ID        string
	AgentID   string
	Type      string
	Payload   string
	Priority  int
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type TaskQueueConfig struct {
	MaxTasks     int
	PriorityMode string
}

func NewTaskQueue(config TaskQueueConfig) *TaskQueue {
	return &TaskQueue{
		tasks:    make(map[string]*QueuedTask),
		priority: make([]string, 0),
	}
}

func (tq *TaskQueue) AddTask(id string, taskType string, payload string) {
	tq.mu.Lock()
	defer tq.mu.Unlock()

	task := &QueuedTask{
		ID:      id,
		Type:    taskType,
		Payload: payload,
		Status:  "pending",
	}

	if task.ID == "" {
		task.ID = generateTaskID()
	}
	task.CreatedAt = time.Now()
	task.UpdatedAt = time.Now()

	tq.tasks[task.ID] = task
	tq.priority = append(tq.priority, task.ID)
}

func (tq *TaskQueue) GetTask(id string) *QueuedTask {
	tq.mu.Lock()
	defer tq.mu.Unlock()

	if task, exists := tq.tasks[id]; exists {
		return task
	}
	return nil
}

func (tq *TaskQueue) CompleteTask(taskID string) {
	tq.mu.Lock()
	defer tq.mu.Unlock()

	if task, exists := tq.tasks[taskID]; exists {
		task.Status = "completed"
		task.UpdatedAt = time.Now()
	}
}

func (tq *TaskQueue) FailTask(taskID string) {
	tq.mu.Lock()
	defer tq.mu.Unlock()

	if task, exists := tq.tasks[taskID]; exists {
		task.Status = "failed"
		task.UpdatedAt = time.Now()
	}
}

func (tq *TaskQueue) GetPendingTasks() []*QueuedTask {
	tq.mu.RLock()
	defer tq.mu.RUnlock()

	tasks := make([]*QueuedTask, 0)
	for _, taskID := range tq.priority {
		if task, exists := tq.tasks[taskID]; exists {
			if task.Status == "pending" {
				tasks = append(tasks, task)
			}
		}
	}
	return tasks
}

func (tq *TaskQueue) GetTaskCount() int {
	tq.mu.RLock()
	defer tq.mu.RUnlock()
	return len(tq.tasks)
}

func (tq *TaskQueue) GetPendingCount() int {
	tq.mu.RLock()
	defer tq.mu.RUnlock()
	return len(tq.priority)
}

func (tq *TaskQueue) RemoveTask(taskID string) {
	tq.mu.Lock()
	defer tq.mu.Unlock()

	delete(tq.tasks, taskID)
	for i, id := range tq.priority {
		if id == taskID {
			tq.priority = append(tq.priority[:i], tq.priority[i+1:]...)
			break
		}
	}
}

func (tq *TaskQueue) Clear() {
	tq.mu.Lock()
	defer tq.mu.Unlock()

	tq.tasks = make(map[string]*QueuedTask)
	tq.priority = make([]string, 0)
}

func (tq *TaskQueue) IsEmpty() bool {
	tq.mu.RLock()
	defer tq.mu.RUnlock()
	return len(tq.priority) == 0
}

func generateTaskID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func formatTaskStatus(status string) string {
	switch status {
	case "pending":
		return "⏳ Pending"
	case "processing":
		return "🔄 Processing"
	case "completed":
		return "✅ Completed"
	case "failed":
		return "❌ Failed"
	default:
		return fmt.Sprintf("Unknown: %s", status)
	}
}
