package orchestrator

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/eventbus"
	"github.com/angel-platform/angel/pkg/logger"
	"github.com/angel-platform/angel/pkg/types"
)

type Dispatcher struct {
	bus    *eventbus.EventBus
	log    *logger.Logger
	tasks  map[string]*TaskStatus
	mu     sync.RWMutex
}

func NewDispatcher(bus *eventbus.EventBus) *Dispatcher {
	return &Dispatcher{
		bus:   bus,
		log:   logger.New("dispatcher", logger.LevelInfo),
		tasks: make(map[string]*TaskStatus),
	}
}

func (d *Dispatcher) Dispatch(agentID string, task *types.Task) error {
	if task == nil {
		return fmt.Errorf("nil task")
	}

	if agentID == "" {
		return fmt.Errorf("empty agent ID")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	status := &TaskStatus{
		TaskID:    task.ID,
		AgentID:   agentID,
		Status:    types.TaskStatusPending,
		StartedAt: time.Now(),
	}

	d.tasks[task.ID] = status

	d.log.Info("Dispatching task %s to agent %s", task.ID, agentID)

	if d.bus != nil {
		d.bus.Publish("task.dispatch", "orchestrator", "command", map[string]interface{}{
			"task_id":  task.ID,
			"agent_id": agentID,
			"type":     string(task.Type),
			"payload":  task.Payload,
		})
	}

	status.Status = types.TaskStatusRunning
	return nil
}

func (d *Dispatcher) DispatchAll(task *types.Task) error {
	if task == nil {
		return fmt.Errorf("nil task")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.log.Info("Dispatching task %s to all agents", task.ID)

	status := &TaskStatus{
		TaskID:    task.ID,
		AgentID:   "*",
		Status:    types.TaskStatusPending,
		StartedAt: time.Now(),
	}

	d.tasks[task.ID] = status

	if d.bus != nil {
		d.bus.Publish("task.dispatch_all", "orchestrator", "command", map[string]interface{}{
			"task_id": task.ID,
			"type":    string(task.Type),
			"payload": task.Payload,
		})
	}

	status.Status = types.TaskStatusRunning
	return nil
}

func (d *Dispatcher) GetStatus(taskID string) (*TaskStatus, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	status, ok := d.tasks[taskID]
	if !ok {
		return nil, fmt.Errorf("task not found: %s", taskID)
	}

	return status, nil
}

func (d *Dispatcher) UpdateStatus(taskID string, status types.TaskStatus, result *types.TaskResult) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	taskStatus, ok := d.tasks[taskID]
	if !ok {
		return fmt.Errorf("task not found: %s", taskID)
	}

	taskStatus.Status = status
	if result != nil {
		taskStatus.Result = &types.TaskResult{
			Module:    result.Module,
			Success:   result.Success,
			Data:      result.Data,
			Error:     result.Error,
			Timestamp: time.Now(),
		}
	}

	if status == types.TaskStatusCompleted || status == types.TaskStatusFailed {
		taskStatus.EndedAt = time.Now()
	}

	return nil
}

func (d *Dispatcher) GetActiveTasks() []*TaskStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var active []*TaskStatus
	for _, status := range d.tasks {
		if status.Status == types.TaskStatusPending || status.Status == types.TaskStatusRunning {
			active = append(active, status)
		}
	}
	return active
}

func (d *Dispatcher) CleanupTasks(maxAge time.Duration) int {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	count := 0

	for id, status := range d.tasks {
		if status.EndedAt.After(cutoff) {
			continue
		}
		if status.Status == types.TaskStatusCompleted || status.Status == types.TaskStatusFailed {
			delete(d.tasks, id)
			count++
		}
	}
	return count
}
