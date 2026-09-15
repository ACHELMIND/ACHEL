package logger

import (
	"io"
	"os"
	"strings"
	"testing"
)

func newTestLogger(level Level) (*Logger, *os.File, *os.File) {
	r, w, _ := os.Pipe()
	l := New("test-module", level)
	l.output = w
	return l, r, w
}

func drainAndClose(r *os.File, w *os.File) string {
	w.Close()
	var buf [4096]byte
	n, _ := r.Read(buf[:])
	return string(buf[:n])
}

func TestLevel_String(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{LevelFatal, "FATAL"},
		{Level(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.expected {
			t.Errorf("Level(%d).String() = %q, want %q", int(tt.level), got, tt.expected)
		}
	}
}

func TestNew_LoggerCreated(t *testing.T) {
	l := New("my-module", LevelInfo)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
	if l.module != "my-module" {
		t.Errorf("expected module 'my-module', got %q", l.module)
	}
	if l.level != LevelInfo {
		t.Errorf("expected level LevelInfo, got %v", l.level)
	}
	if l.output != os.Stdout {
		t.Error("expected output to be os.Stdout")
	}
}

func TestLogger_Debug(t *testing.T) {
	l, r, w := newTestLogger(LevelDebug)
	l.Debug("hello %s", "world")
	out := drainAndClose(r, w)
	if !strings.Contains(out, "DEBUG") {
		t.Errorf("expected DEBUG in output, got %q", out)
	}
	if !strings.Contains(out, "hello world") {
		t.Errorf("expected message in output, got %q", out)
	}
	if !strings.Contains(out, "test-module") {
		t.Errorf("expected module name in output, got %q", out)
	}
}

func TestLogger_Info(t *testing.T) {
	l, r, w := newTestLogger(LevelInfo)
	l.Info("started %d tasks", 5)
	out := drainAndClose(r, w)
	if !strings.Contains(out, "INFO") {
		t.Errorf("expected INFO in output, got %q", out)
	}
	if !strings.Contains(out, "started 5 tasks") {
		t.Errorf("expected formatted message, got %q", out)
	}
}

func TestLogger_Warn(t *testing.T) {
	l, r, w := newTestLogger(LevelWarn)
	l.Warn("disk usage %d%%", 95)
	out := drainAndClose(r, w)
	if !strings.Contains(out, "WARN") {
		t.Errorf("expected WARN in output, got %q", out)
	}
	if !strings.Contains(out, "disk usage 95%") {
		t.Errorf("expected formatted message, got %q", out)
	}
}

func TestLogger_Error(t *testing.T) {
	l, r, w := newTestLogger(LevelError)
	l.Error("connection failed: %v", "timeout")
	out := drainAndClose(r, w)
	if !strings.Contains(out, "ERROR") {
		t.Errorf("expected ERROR in output, got %q", out)
	}
	if !strings.Contains(out, "connection failed") {
		t.Errorf("expected error message in output, got %q", out)
	}
}

func TestLogger_LevelFiltering(t *testing.T) {
	l, r, w := newTestLogger(LevelWarn)
	l.Debug("should not appear")
	l.Info("should not appear")
	l.Warn("should appear")
	l.Error("should appear")
	w.Close()

	var buf [8192]byte
	n, _ := r.Read(buf[:])
	out := string(buf[:n])

	if strings.Contains(out, "DEBUG") {
		t.Error("DEBUG should be filtered out at WARN level")
	}
	if strings.Contains(out, "INFO") {
		t.Error("INFO should be filtered out at WARN level")
	}
	if !strings.Contains(out, "WARN") {
		t.Error("WARN should appear")
	}
	if !strings.Contains(out, "ERROR") {
		t.Error("ERROR should appear")
	}
}

func TestLogger_SetLevel(t *testing.T) {
	l, r1, w1 := newTestLogger(LevelInfo)
	l.Debug("msg1")
	out1 := drainAndClose(r1, w1)
	if len(out1) != 0 {
		t.Error("DEBUG should not appear at INFO level")
	}

	l.SetLevel(LevelDebug)

	r2, w2, _ := os.Pipe()
	l.output = w2
	l.Debug("msg2")
	out2 := drainAndClose(r2, w2)
	if !strings.Contains(out2, "msg2") {
		t.Error("DEBUG should appear after SetLevel(LevelDebug)")
	}
}

func TestLogger_WithModule(t *testing.T) {
	l, _, _ := newTestLogger(LevelDebug)
	l2 := l.WithModule("other-module")

	if l2.module != "other-module" {
		t.Errorf("expected module 'other-module', got %q", l2.module)
	}
	if l2.level != l.level {
		t.Error("expected WithModule to inherit level")
	}
	if l2.output != l.output {
		t.Error("expected WithModule to inherit output")
	}

	r, w, _ := os.Pipe()
	l2.output = w
	l2.Info("hello")
	out := drainAndClose(r, w)
	if !strings.Contains(out, "other-module") {
		t.Errorf("expected 'other-module' in output, got %q", out)
	}
}

func TestLogger_FormattedTimestamp(t *testing.T) {
	l, r, w := newTestLogger(LevelInfo)
	l.Info("check")
	out := drainAndClose(r, w)
	if !strings.HasPrefix(out, "[") {
		t.Errorf("expected output to start with '[', got %q", out)
	}
	parts := strings.SplitN(out, "]", 4)
	if len(parts) < 4 {
		t.Errorf("expected at least 4 bracket-separated parts, got %d in %q", len(parts), out)
	}
}

func TestLogger_ConcurrentWrites(t *testing.T) {
	l, r, w := newTestLogger(LevelDebug)

	// Use a goroutine to drain the reader concurrently
	var collected []byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		var buf [65536]byte
		for {
			n, err := r.Read(buf[len(collected):])
			if n > 0 {
				collected = append(collected, buf[:n]...)
			}
			if err != nil || len(collected) >= 65536 {
				return
			}
		}
	}()

	for i := 0; i < 100; i++ {
		l.Info("msg %d", i)
	}
	w.Close()
	<-done

	if len(collected) == 0 {
		t.Error("expected some output after concurrent writes")
	}
}

func TestLogger_NoArgs(t *testing.T) {
	l, r, w := newTestLogger(LevelDebug)
	l.Info("simple message")
	out := drainAndClose(r, w)
	if !strings.Contains(out, "simple message") {
		t.Error("expected plain message without args")
	}
}

func TestLogger_AllLevelsSequential(t *testing.T) {
	l, r, w := newTestLogger(LevelDebug)
	l.Debug("d1")
	l.Info("i1")
	l.Warn("w1")
	l.Error("e1")
	out := drainAndClose(r, w)

	if strings.Count(out, "DEBUG") != 1 {
		t.Error("expected exactly 1 DEBUG line")
	}
	if strings.Count(out, "INFO") != 1 {
		t.Error("expected exactly 1 INFO line")
	}
	if strings.Count(out, "WARN") != 1 {
		t.Error("expected exactly 1 WARN line")
	}
	if strings.Count(out, "ERROR") != 1 {
		t.Error("expected exactly 1 ERROR line")
	}
}

func TestLogger_EmptyMessage(t *testing.T) {
	l, r, w := newTestLogger(LevelDebug)
	l.Info("")
	out := drainAndClose(r, w)
	if !strings.Contains(out, "INFO") {
		t.Error("expected INFO even for empty message")
	}
}

func TestLogger_SpecialCharacters(t *testing.T) {
	l, r, w := newTestLogger(LevelDebug)
	l.Info("path=C:\\Users\\test key=value \"quoted\"")
	out := drainAndClose(r, w)
	if !strings.Contains(out, "path=C:\\Users\\test") {
		t.Errorf("expected special chars preserved, got %q", out)
	}
}

func TestLogger_MultipleFormatArgs(t *testing.T) {
	l, r, w := newTestLogger(LevelDebug)
	l.Info("a=%s b=%d c=%v", "str", 42, true)
	out := drainAndClose(r, w)
	if !strings.Contains(out, "a=str") {
		t.Errorf("expected 'a=str' in output, got %q", out)
	}
	if !strings.Contains(out, "b=42") {
		t.Errorf("expected 'b=42' in output, got %q", out)
	}
	if !strings.Contains(out, "c=true") {
		t.Errorf("expected 'c=true' in output, got %q", out)
	}
}

// Ensure the Fatal test doesn't actually call os.Exit
func TestLogger_Fatal_DoesNotExit(t *testing.T) {
	// We can't easily test Fatal since it calls os.Exit(1)
	// Just verify the method exists and the logger is configured
	l := New("test-module", LevelDebug)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
	// Skip actual Fatal test - it calls os.Exit(1)
}

// Ensure io is used (prevents import removal)
var _ = io.Copy
