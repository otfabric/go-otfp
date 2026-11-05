// SPDX-License-Identifier: MIT

//go:build windows

package wire

import (
	"errors"
	"syscall"
)

// wsaeMsgSize is WSAEMSGSIZE: a datagram larger than the read buffer.
const wsaeMsgSize = syscall.Errno(10040)

// msgTooLarge reports whether a datagram read failed because the datagram
// did not fit the buffer, which Windows reports as WSAEMSGSIZE.
var msgTooLarge = func(err error) bool { return errors.Is(err, wsaeMsgSize) }

// portUnreachable reports whether a connected UDP read failed on an ICMP
// port unreachable, which Windows reports as WSAECONNRESET.
var portUnreachable = func(err error) bool { return errors.Is(err, syscall.WSAECONNRESET) }
