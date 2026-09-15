package langgraph

import (
	"fmt"
	"sync"
	"time"
)

type Graph struct {
	nodes   map[string]*Node
	edges   map[string][]string
	state   map[string]interface{}
	mu      sync.RWMutex
	running bool
}

type Node struct {
	ID       string
	Name     string
	Type     NodeType
	Execute  func(state map[string]interface{}) (map[string]interface{}, error)
	Metadata map[string]interface{}
}

type NodeType string

const (
	NodeTypeAction    NodeType = "action"
	NodeTypeCondition NodeType = "condition"
	NodeTypeRouter    NodeType = "router"
	NodeTypeParallel  NodeType = "parallel"
	NodeTypeStart     NodeType = "start"
	NodeTypeEnd       NodeType = "end"
)

func NewGraph() *Graph {
	return &Graph{
		nodes: make(map[string]*Node),
		edges: make(map[string][]string),
		state: make(map[string]interface{}),
	}
}

func (g *Graph) AddNode(id, name string, nodeType NodeType, exec func(state map[string]interface{}) (map[string]interface{}, error)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[id] = &Node{
		ID:       id,
		Name:     name,
		Type:     nodeType,
		Execute:  exec,
		Metadata: make(map[string]interface{}),
	}
}

func (g *Graph) AddEdge(from, to string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges[from] = append(g.edges[from], to)
}

func (g *Graph) SetState(key string, value interface{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.state[key] = value
}

func (g *Graph) GetState(key string) interface{} {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.state[key]
}

func (g *Graph) Run(startNode string) error {
	g.mu.Lock()
	g.running = true
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		g.running = false
		g.mu.Unlock()
	}()

	current := startNode
	visited := make(map[string]bool)

	for current != "" {
		if visited[current] {
			return fmt.Errorf("cycle detected at node %s", current)
		}
		visited[current] = true

		node, exists := g.nodes[current]
		if !exists {
			return fmt.Errorf("node %s not found", current)
		}

		var err error
		if node.Execute != nil {
			result, execErr := node.Execute(g.state)
			if execErr != nil {
				return fmt.Errorf("node %s execution failed: %w", current, execErr)
			}
			g.mu.Lock()
			for k, v := range result {
				g.state[k] = v
			}
			g.mu.Unlock()
		}

		nextNodes := g.edges[current]
		if len(nextNodes) == 0 {
			break
		}
		if len(nextNodes) == 1 {
			current = nextNodes[0]
		} else {
			for _, next := range nextNodes {
				if err = g.runParallel(next, visited); err != nil {
					return err
				}
			}
			break
		}
		_ = err
	}

	return nil
}

func (g *Graph) runParallel(startNode string, visited map[string]bool) error {
	current := startNode
	for current != "" {
		if visited[current] {
			return nil
		}
		visited[current] = true

		node, exists := g.nodes[current]
		if !exists {
			return fmt.Errorf("node %s not found", current)
		}

		if node.Execute != nil {
			result, err := node.Execute(g.state)
			if err != nil {
				return err
			}
			g.mu.Lock()
			for k, v := range result {
				g.state[k] = v
			}
			g.mu.Unlock()
		}

		nextNodes := g.edges[current]
		if len(nextNodes) == 0 {
			break
		}
		current = nextNodes[0]
	}
	return nil
}

func (g *Graph) Reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.state = make(map[string]interface{})
	g.running = false
}

func (g *Graph) IsRunning() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.running
}

func (g *Graph) GetStateSnapshot() map[string]interface{} {
	g.mu.RLock()
	defer g.mu.RUnlock()
	snapshot := make(map[string]interface{})
	for k, v := range g.state {
		snapshot[k] = v
	}
	return snapshot
}

func ExecuteWithTimeout(g *Graph, startNode string, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		done <- g.Run(startNode)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("graph execution timed out after %s", timeout)
	}
}
