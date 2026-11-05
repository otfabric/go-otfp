// SPDX-License-Identifier: MIT

//go:build windows

package core

import (
	"errors"
	"syscall"
)

// wsaeConnRefused is WSAECONNREFUSED, the error Windows returns for a
// refused connection. The syscall package's ECONNREFUSED is an invented
// value on Windows that no system call returns.
const wsaeConnRefused = syscall.Errno(10061)

// isRefused reports whether err is a refused connection.
func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaeConnRefused)
}
