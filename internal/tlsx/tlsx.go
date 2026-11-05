// SPDX-License-Identifier: MIT

// Package tlsx holds the one TLS client configuration the fingerprinters
// use.
package tlsx

import "crypto/tls"

// Fingerprint returns a new TLS client configuration that does not verify
// the server's certificate chain or host name.
//
// Fingerprinting identifies an endpoint; it does not trust it. Nothing
// sent over these connections is secret (a handshake, a read-only identity
// request), and nothing received is acted on beyond reporting it. OT
// devices commonly present self-signed or expired certificates, or
// certificates for a name other than the address probed, and the
// certificate itself is part of what is reported. Verifying would turn
// those devices into "not detected" without making the probe any safer.
// Callers that need a verified connection pass their own core.Target.TLS.
//
// MinVersion is TLS 1.2, the crypto/tls client default, stated so the
// versions offered do not change with a GODEBUG setting.
func Fingerprint() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}
