// SPDX-License-Identifier: MIT

package ieee2030

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// The subject of the server certificate and the pollRate of /dcap reach the
// identity as text only.
func TestCertificateSubjectAndPollRateAreText(t *testing.T) {
	nt := fuzzkit.NonText[:len(fuzzkit.NonText)-1] // a UTF8String of a certificate is valid UTF-8
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "server" + nt + " one", Organization: []string{"Org" + nt}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	body := `<DeviceCapability xmlns="urn:ieee:std:2030.5:ns" href="/dcap" pollRate="9` + fuzzkit.NonText + `00"><TimeLink href="/tm"/></DeviceCapability>`
	reply := "HTTP/1.1 200 OK\r\nContent-Type: application/sep+xml\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
	tg := tlsServer(t, cfg, reply)
	r, err := New().Detect(context.Background(), tg, core.Options{})
	fuzzkit.Check(t, proto, r, err)
	if !r.Matched || r.Identity == nil {
		t.Fatalf("%v", r)
	}
	if got := r.Identity.Attributes["pollRate"]; got != "900" {
		t.Errorf("pollRate %q, want %q", got, "900")
	}
	subject := r.Identity.Attributes["serverCertSubject"]
	if !strings.Contains(subject, "CN=server one") || !strings.Contains(subject, "O=Org") {
		t.Errorf("serverCertSubject %q", subject)
	}
}
