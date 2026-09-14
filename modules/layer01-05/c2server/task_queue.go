package c2server

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type TaskQueue struct {
	mu     sync.RWMutex
	queues map[string][]*types.Task
}

func NewTaskQueue() *TaskQueue {
	return &TaskQueue{
		queues: make(map[string][]*types.Task),
	}
}

func (tq *TaskQueue) Enqueue(agentID string, task *types.Task) error {
	if task == nil {
		return fmt.Errorf("task cannot be nil")
	}
	tq.mu.Lock()
	defer tq.mu.Unlock()
	tq.queues[agentID] = append(tq.queues[agentID], task)
	return nil
}

func (tq *TaskQueue) Dequeue(agentID string) (*types.Task, bool) {
	tq.mu.Lock()
	defer tq.mu.Unlock()
	queue := tq.queues[agentID]
	if len(queue) == 0 {
		return nil, false
	}
	task := queue[0]
	tq.queues[agentID] = queue[1:]
	return task, true
}

func (tq *TaskQueue) Peek(agentID string) (*types.Task, bool) {
	tq.mu.RLock()
	defer tq.mu.RUnlock()
	queue := tq.queues[agentID]
	if len(queue) == 0 {
		return nil, false
	}
	return queue[0], true
}

func (tq *TaskQueue) GetPendingCount(agentID string) int {
	tq.mu.RLock()
	defer tq.mu.RUnlock()
	return len(tq.queues[agentID])
}

func (tq *TaskQueue) MarkComplete(taskID string) error {
	tq.mu.Lock()
	defer tq.mu.Unlock()
	for agentID, queue := range tq.queues {
		for i, task := range queue {
			if task.ID == taskID {
				task.Status = types.TaskStatusCompleted
				task.EndedAt = time.Now()
				tq.queues[agentID] = append(queue[:i], queue[i+1:]...)
				return nil
			}
		}
	}
	return fmt.Errorf("task not found: %s", taskID)
}

func (tq *TaskQueue) MarkFailed(taskID string, err error) error {
	tq.mu.Lock()
	defer tq.mu.Unlock()
	for agentID, queue := range tq.queues {
		for i, task := range queue {
			if task.ID == taskID {
				task.Status = types.TaskStatusFailed
				task.EndedAt = time.Now()
				if err != nil {
					task.Error = err.Error()
				}
				tq.queues[agentID] = append(queue[:i], queue[i+1:]...)
				return nil
			}
		}
	}
	return fmt.Errorf("task not found: %s", taskID)
}
