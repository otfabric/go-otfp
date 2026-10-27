// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"fmt"
	"log/slog"
)

// Logger receives debug and diagnostic output. Logging is silent by
// default. Methods are called synchronously and must not block.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// NopLogger returns a Logger that discards everything.
func NopLogger() Logger { return nopLogger{} }

type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

// NewSlogLogger adapts a slog.Handler. Messages are only formatted when the
// handler is enabled for their level. A nil handler returns NopLogger.
func NewSlogLogger(h slog.Handler) Logger {
	if h == nil {
		return nopLogger{}
	}
	return slogLogger{h: h, l: slog.New(h)}
}

type slogLogger struct {
	h slog.Handler
	l *slog.Logger
}

func (s slogLogger) logf(level slog.Level, f string, a []any) {
	if s.h.Enabled(context.Background(), level) {
		s.l.Log(context.Background(), level, fmt.Sprintf(f, a...))
	}
}

func (s slogLogger) Debugf(f string, a ...any) { s.logf(slog.LevelDebug, f, a) }
func (s slogLogger) Infof(f string, a ...any)  { s.logf(slog.LevelInfo, f, a) }
func (s slogLogger) Warnf(f string, a ...any)  { s.logf(slog.LevelWarn, f, a) }
func (s slogLogger) Errorf(f string, a ...any) { s.logf(slog.LevelError, f, a) }
