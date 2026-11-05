// SPDX-License-Identifier: MIT

package tlsx

import (
	"crypto/tls"
	"testing"
)

func TestFingerprint(t *testing.T) {
	a, b := Fingerprint(), Fingerprint()
	if !a.InsecureSkipVerify || a.MinVersion != tls.VersionTLS12 || a.MaxVersion != 0 {
		t.Fatalf("%+v", a)
	}
	if a == b {
		t.Fatal("Fingerprint shares one configuration")
	}
}
