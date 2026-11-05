// SPDX-License-Identifier: MIT

//go:build !windows

package wire

// msgTooLarge reports whether a datagram read failed because the datagram
// did not fit the buffer. Unix truncates such a datagram silently instead.
// A variable, so that tests can exercise the Windows behaviour.
var msgTooLarge = func(error) bool { return false }

// portUnreachable reports whether a connected UDP read failed on an ICMP
// port unreachable that the error classification does not already map to a
// refused connection. Unix reports it as ECONNREFUSED, which it does.
var portUnreachable = func(error) bool { return false }
