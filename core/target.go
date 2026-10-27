// SPDX-License-Identifier: MIT

package core

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"
)

// DefaultTimeout is the per-operation timeout used when Target.Timeout is
// zero.
const DefaultTimeout = 3 * time.Second

// Target is the endpoint to fingerprint.
type Target struct {
	// Host is an IP address or a host name.
	Host string

	// Port is the TCP or UDP port.
	Port int

	// Network restricts detection to fingerprinters of one transport. The
	// zero value is TCP. Use UDP to probe BACnet/IP, the EtherNet/IP
	// ListIdentity service on UDP or PROFINET's DCE/RPC endpoint.
	Network Network

	// Timeout bounds each dial, write and read of a fingerprinter. The
	// zero value is DefaultTimeout.
	Timeout time.Duration

	// TLS, when non-nil, makes TCP fingerprinters run over TLS with this
	// configuration: Modbus/TCP Security, IEC 62351-3 for IEC 104 and
	// DNP3, EtherNet/IP over TLS, OCPP over wss://, OpenADR over HTTPS.
	// ServerName defaults to Host. Fingerprinters that negotiate TLS
	// themselves (IEEE 2030.5) start from a clone of it.
	TLS *tls.Config

	// Path, when set, overrides the HTTP or WebSocket path the web-based
	// fingerprinters (OCPP, IEEE 2030.5, OpenADR) try first.
	Path string
}

// EffectiveTimeout returns Timeout, or DefaultTimeout when it is zero.
func (t Target) EffectiveTimeout() time.Duration {
	if t.Timeout <= 0 {
		return DefaultTimeout
	}
	return t.Timeout
}

// Addr returns the target as "host:port", with IPv6 addresses bracketed.
func (t Target) Addr() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// String returns network://host:port, e.g. "tcp://10.0.0.5:502", with
// "+tls" appended to the scheme when TLS is set.
func (t Target) String() string {
	scheme := t.Network.String()
	if t.TLS != nil && t.Network == TCP {
		scheme += "+tls"
	}
	return scheme + "://" + t.Addr()
}

// Validate reports the first malformed field: an empty Host, a Port outside
// 1..65535, a negative Timeout, an unknown Network or TLS on UDP.
func (t Target) Validate() error {
	if t.Host == "" {
		return fmt.Errorf("empty host")
	}
	if t.Port < 1 || t.Port > 65535 {
		return fmt.Errorf("port %d out of range 1..65535", t.Port)
	}
	if t.Timeout < 0 {
		return fmt.Errorf("negative timeout %v", t.Timeout)
	}
	switch t.Network {
	case TCP:
	case UDP:
		if t.TLS != nil {
			return fmt.Errorf("TLS is not supported over UDP")
		}
	default:
		return fmt.Errorf("unknown network %d", t.Network)
	}
	return nil
}

// ParseTarget parses "host:port", "[v6]:port" or "network://host:port"
// where network is tcp, udp or tls (TCP with a default TLS configuration
// that does not verify the server certificate, as fingerprinting needs).
func ParseTarget(s string) (Target, error) {
	var t Target
	if i := indexScheme(s); i >= 0 {
		switch s[:i] {
		case "tcp":
		case "udp":
			t.Network = UDP
		case "tls", "tcp+tls":
			t.TLS = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // fingerprinting identifies, it does not trust
		default:
			return Target{}, fmt.Errorf("unknown scheme %q (want tcp, udp or tls)", s[:i])
		}
		s = s[i+3:]
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return Target{}, fmt.Errorf("target %q: %w", s, err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return Target{}, fmt.Errorf("target %q: port %q is not a number", s, port)
	}
	t.Host, t.Port = host, p
	return t, t.Validate()
}

func indexScheme(s string) int {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == ':' {
			if s[i+1] == '/' && s[i+2] == '/' {
				return i
			}
			return -1
		}
	}
	return -1
}
