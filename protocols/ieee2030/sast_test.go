// SPDX-License-Identifier: MIT

package ieee2030

import (
	"crypto/tls"
	"encoding/binary"
	"strings"
	"testing"
)

// A server name too long for the 16-bit length fields used to wrap them:
// with 70000 octets the record claimed 4569 of its 70105 octets.
// Names that cannot be DNS host names are now left out of the hello.
func TestClientHelloLongServerName(t *testing.T) {
	plain := clientHello("")
	for _, n := range []int{maxServerName + 1, 70000} {
		ch := clientHello(strings.Repeat("a", n))
		if rl := int(binary.BigEndian.Uint16(ch[3:5])); rl != len(ch)-5 {
			t.Fatalf("%d-octet name: record length %d, %d octets", n, rl, len(ch)-5)
		}
		if len(ch) != len(plain) {
			t.Fatalf("%d-octet name was sent", n)
		}
	}
	ch := clientHello(strings.Repeat("a", maxServerName))
	if len(ch) != len(plain)+4+5+maxServerName {
		t.Fatalf("a %d-octet name: %d octets, without %d", maxServerName, len(ch), len(plain))
	}
	hl := int(ch[6])<<16 | int(binary.BigEndian.Uint16(ch[7:9]))
	if ch[5] != 1 || hl != len(ch)-9 {
		t.Fatalf("handshake type %d length %d, %d octets", ch[5], hl, len(ch)-9)
	}
}

// The dcap handshake keeps the fingerprinting TLS configuration.
func TestDcapTLSConfig(t *testing.T) {
	cfg := dcapConfig("utility.example")
	if !cfg.InsecureSkipVerify || cfg.MinVersion != tls.VersionTLS12 || cfg.ServerName != "utility.example" || cfg.GetClientCertificate == nil {
		t.Fatalf("%+v", cfg)
	}
	if c, err := cfg.GetClientCertificate(nil); err != nil || len(c.Certificate) != 0 {
		t.Fatalf("%v %v", c, err)
	}
	if dcapConfig("10.0.0.5").ServerName != "" {
		t.Fatal("ServerName set for an IP address")
	}
}
