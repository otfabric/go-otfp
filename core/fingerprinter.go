// SPDX-License-Identifier: MIT

package core

import "context"

// Mode selects how far a fingerprinter goes.
type Mode uint8

// Modes.
const (
	// ModeDetect performs the minimal exchange that tells whether the
	// endpoint speaks the protocol: a handshake or one harmless request.
	ModeDetect Mode = iota
	// ModeIdentify additionally sends the protocol's standard read-only
	// identity requests (Read Device Identification, Identity object,
	// SZL, Identify, ReadProperty of the Device object, GetEndpoints ...)
	// and fills Result.Identity. It never writes, controls or changes
	// configuration.
	ModeIdentify
)

// String returns "detect" or "identify".
func (m Mode) String() string {
	if m == ModeIdentify {
		return "identify"
	}
	return "detect"
}

// Options configure one detection attempt.
type Options struct {
	// Mode is ModeDetect (the default) or ModeIdentify.
	Mode Mode
	// Trace records every probe and response in Result.Exchanges.
	Trace bool
	// Logger receives debug output of the exchange. Nil is silent.
	Logger Logger
	// MaxIntrusiveness is the most the scan allows. Fingerprinters whose
	// Info.Intrusiveness exceeds it are not run; the others may use it to
	// decide on optional fallbacks (Modbus reads one holding register
	// when Read Device Identification is not supported, but only when
	// ReadOnly is allowed).
	MaxIntrusiveness Intrusiveness
}

// Log returns the logger, never nil.
func (o Options) Log() Logger {
	if o.Logger == nil {
		return NopLogger()
	}
	return o.Logger
}

// Intrusiveness grades what a fingerprinter puts on the wire, so that
// careful scans can skip the noisier ones.
type Intrusiveness uint8

// Intrusiveness levels.
const (
	// Passive fingerprinters send a protocol's standard connection
	// handshake or discovery request only (COTP CR, HEL, Who-Is,
	// ListIdentity, STARTDT, WebSocket upgrade, HTTP GET).
	Passive Intrusiveness = iota
	// ReadOnly fingerprinters also send read requests to application
	// data, such as Modbus holding registers for the SunSpec marker.
	ReadOnly
)

// String returns "passive" or "read-only".
func (i Intrusiveness) String() string {
	if i == ReadOnly {
		return "read-only"
	}
	return "passive"
}

// Info describes a fingerprinter.
type Info struct {
	// Protocol is what the fingerprinter detects.
	Protocol Protocol
	// Network is the transport it probes over.
	Network Network
	// Ports are the well-known ports of the protocol. The engine tries
	// fingerprinters whose Ports include the target port first.
	Ports []int
	// Priority orders fingerprinters among themselves (lower first),
	// after the port preference.
	Priority int
	// Intrusiveness grades what the fingerprinter sends.
	Intrusiveness Intrusiveness
	// Refines names the protocol this one is a profile of (SunSpec
	// refines Modbus): after an early stop on that protocol the engine
	// still runs this fingerprinter, and prefers it as the best match.
	Refines Protocol
	// Description summarises the probe sequence, e.g.
	// "TPKT/COTP CR (TSAP 0x0100/0x0102), S7 Setup Communication, SZL 0x0011/0x001C".
	Description string
}

// Fingerprinter detects one protocol. Implementations must be safe for
// concurrent use, honour ctx and Target.Timeout, and never panic on any
// response.
type Fingerprinter interface {
	// Info describes the fingerprinter. It must return the same value on
	// every call.
	Info() Info

	// Detect probes target. A non-nil error means detection could not
	// decide (the endpoint was unreachable or timed out); a response that
	// is merely not this protocol is a NoMatch result with a nil error.
	Detect(ctx context.Context, target Target, opts Options) (Result, error)
}
