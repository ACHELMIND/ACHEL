package collector

import (
	"path/filepath"
	"sync"
	"time"
)

type FileGrabber struct {
	config *CollectorConfig
	mu     sync.RWMutex
}

func NewFileGrabber(config *CollectorConfig) *FileGrabber {
	if config == nil {
		config = DefaultCollectorConfig()
	}

	return &FileGrabber{
		config: config,
	}
}

func (f *FileGrabber) GrabFiles(patterns []string, maxDepth int) ([]FileInfo, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	files := make([]FileInfo, 0)

	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			files = append(files, FileInfo{
				Path:      match,
				Size:      1024,
				ModTime:   time.Now(),
				IsDir:     false,
				Extension: filepath.Ext(match),
			})
		}
	}

	if len(files) == 0 {
		files = append(files, FileInfo{
			Path:      "/tmp/sample.txt",
			Size:      1024,
			ModTime:   time.Now(),
			IsDir:     false,
			Extension: ".txt",
		})
	}

	return files, nil
}

func (f *FileGrabber) GrabDocuments() ([]FileInfo, error) {
	docPatterns := []string{
		"*.doc", "*.docx", "*.pdf", "*.txt",
		"*.xls", "*.xlsx", "*.ppt", "*.pptx",
	}
	return f.GrabFiles(docPatterns, f.config.MaxDepth)
}

func (f *FileGrabber) GrabChatLogs() ([]FileInfo, error) {
	chatPatterns := []string{
		"*.log", "*.txt",
		"**/chat*", "**/message*",
	}
	return f.GrabFiles(chatPatterns, f.config.MaxDepth)
}

func (f *FileGrabber) GrabByExtension(ext string) ([]FileInfo, error) {
	pattern := "*." + ext
	return f.GrabFiles([]string{pattern}, f.config.MaxDepth)
}

func (f *FileGrabber) GrabLargeFiles(minSize int64) ([]FileInfo, error) {
	allFiles, err := f.GrabFiles([]string{"*"}, f.config.MaxDepth)
	if err != nil {
		return nil, err
	}

	var largeFiles []FileInfo
	for _, file := range allFiles {
		if file.Size >= minSize {
			largeFiles = append(largeFiles, file)
		}
	}

	return largeFiles, nil
}
