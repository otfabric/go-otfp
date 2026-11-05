// SPDX-License-Identifier: MIT

package core

import (
	"crypto/tls"
	"testing"
)

func TestParseTargetTLSConfig(t *testing.T) {
	a, err := ParseTarget("tls://127.0.0.1:8883")
	if err != nil || a.TLS == nil || !a.TLS.InsecureSkipVerify || a.TLS.MinVersion != tls.VersionTLS12 {
		t.Fatalf("%+v %v", a.TLS, err)
	}
	b, _ := ParseTarget("tcp+tls://127.0.0.1:8883")
	if b.TLS == a.TLS {
		t.Fatal("targets share one TLS configuration")
	}
}
