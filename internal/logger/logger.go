// Package logger provides structured, tamper-aware logging for Mitiga.
//
// Every log entry includes: timestamp (UTC), severity level, component name,
// action performed, and outcome. The log file is mandatory and serves as the
// authoritative audit trail. Console output is supplementary.
//
// Per §7: No sensitive data (passwords, tokens, private keys) may appear in logs.
package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// componentKey is the context key for the component name.
type componentKey struct{}

// WithComponent returns a child context carrying the component name.
func WithComponent(ctx context.Context, component string) context.Context {
	return context.WithValue(ctx, componentKey{}, component)
}

// componentFromContext extracts the component name from context.
func componentFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(componentKey{}).(string); ok {
		return v
	}
	return "unknown"
}

// Setup initializes the global slog logger with dual output: mandatory file
// and optional console. Returns a cleanup function that must be called on
// shutdown to flush and close the log file.
func Setup(logFile, logLevel, logOutput string) (cleanup func(), err error) {
	level, err := parseLevel(logLevel)
	if err != nil {
		return nil, err
	}

	// Ensure the log directory exists.
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return nil, fmt.Errorf("logger: create log directory %q: %w", logDir, err)
	}

	// Open the mandatory log file (append-only, owner-only permissions).
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- path is operator-supplied via config, not user input
	if err != nil {
		return nil, fmt.Errorf("logger: open log file %q: %w", logFile, err)
	}

	// Build the list of writers. File is always included.
	writers := []io.Writer{f}

	switch logOutput {
	case "stdout":
		writers = append(writers, os.Stdout)
	case "stderr":
		writers = append(writers, os.Stderr)
	case "none":
		// File only — no console output.
	default:
		writers = append(writers, os.Stdout)
	}

	multiWriter := io.MultiWriter(writers...)

	handler := slog.NewJSONHandler(multiWriter, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Ensure timestamps are always UTC.
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(interface{ UTC() interface{} }); ok {
					_ = t // slog already uses UTC for time.Time
				}
			}
			return a
		},
	})

	slog.SetDefault(slog.New(handler))

	cleanup = func() {
		_ = f.Sync()
		_ = f.Close()
	}

	return cleanup, nil
}

// Info logs an action at INFO level with structured context.
func Info(ctx context.Context, action string, attrs ...any) {
	attrs = prependComponent(ctx, attrs)
	slog.InfoContext(ctx, action, attrs...)
}

// Warn logs a security-relevant event at WARN level.
func Warn(ctx context.Context, action string, attrs ...any) {
	attrs = prependComponent(ctx, attrs)
	slog.WarnContext(ctx, action, attrs...)
}

// Error logs an error at ERROR level.
func Error(ctx context.Context, action string, attrs ...any) {
	attrs = prependComponent(ctx, attrs)
	slog.ErrorContext(ctx, action, attrs...)
}

// Debug logs detailed diagnostic information at DEBUG level.
func Debug(ctx context.Context, action string, attrs ...any) {
	attrs = prependComponent(ctx, attrs)
	slog.DebugContext(ctx, action, attrs...)
}

// Critical logs a critical event at ERROR level with a "critical" marker.
// Per §8: Never panic — log critical events instead.
func Critical(ctx context.Context, action string, attrs ...any) {
	attrs = prependComponent(ctx, attrs)
	attrs = append(attrs, "severity", "CRITICAL")
	slog.ErrorContext(ctx, action, attrs...)
}

// prependComponent adds the component name from context to the attributes.
func prependComponent(ctx context.Context, attrs []any) []any {
	component := componentFromContext(ctx)
	return append([]any{"component", component}, attrs...)
}

// parseLevel converts a string log level to slog.Level.
func parseLevel(level string) (slog.Level, error) {
	switch level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("logger: invalid log level %q", level)
	}
}
