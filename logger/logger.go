package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxLines = 5000

var (
	lines []string
	mu    sync.RWMutex

	// File persistence state, guarded by fileMu.
	logFile    *os.File
	fileMu     sync.Mutex
	filePath   string
	fileWarned bool
)

// Init 替换标准 log 输出，同时保留控制台输出
func Init() {
	log.SetFlags(0)
	log.SetOutput(&writer{})
}

type writer struct{}

// SetFilePath sets the log file path for persistence.
// It closes the old file, creates parent dirs, and opens the new
// file lazily in append mode. An empty path disables file output.
func SetFilePath(path string) {
	fileMu.Lock()
	defer fileMu.Unlock()

	// Close old file first.
	if logFile != nil {
		logFile.Close()
		logFile = nil
	}
	filePath = path
	fileWarned = false

	if path == "" {
		return
	}
	// Create parent directory if needed.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintln(os.Stderr, "logger: MkdirAll failed:", err)
			return
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "logger: open log file failed:", err)
		return
	}
	logFile = f
}

// GetFilePath returns the current log file path (empty if disabled).
func GetFilePath() string {
	fileMu.Lock()
	defer fileMu.Unlock()
	return filePath
}

// appendToFile writes one formatted line to the log file (best-effort).
// The caller must NOT hold fileMu; errors are reported to stderr once.
func appendToFile(line string) {
	fileMu.Lock()
	defer fileMu.Unlock()
	if logFile == nil || filePath == "" {
		return
	}
	if _, err := logFile.WriteString(line + "\n"); err != nil {
		if !fileWarned {
			fileWarned = true
			fmt.Fprintln(os.Stderr, "logger: write log file failed:", err)
		}
	}
}

func (w *writer) Write(p []byte) (n int, err error) {
	line := strings.TrimRight(string(p), "\n")
	now := time.Now()
	tsShort := now.Format("15:04:05")
	tsFull := now.Format("2006-01-02 15:04:05")
	formatted := fmt.Sprintf("[%s] %s", tsShort, line)
	fileLine := fmt.Sprintf("[%s] %s", tsFull, line)

	mu.Lock()
	lines = append(lines, formatted)
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	mu.Unlock()

	// Persist to file (best-effort, never fails the caller).
	appendToFile(fileLine)

	// 同时输出到控制台
	fmt.Println(formatted)
	return len(p), nil
}

// GetLines 返回最近 N 条日志
func GetLines(n int) []string {
	mu.RLock()
	defer mu.RUnlock()
	if n <= 0 || n > len(lines) {
		n = len(lines)
	}
	result := make([]string, n)
	copy(result, lines[len(lines)-n:])
	return result
}
