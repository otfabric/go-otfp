// SPDX-License-Identifier: MIT

//go:build !windows

package core

import (
	"errors"
	"syscall"
)

// isRefused reports whether err is a refused connection (ECONNREFUSED,
// also what a connected UDP socket reads after an ICMP port unreachable).
func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
