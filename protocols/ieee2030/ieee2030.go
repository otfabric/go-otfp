// SPDX-License-Identifier: MIT

// Package ieee2030 fingerprints IEEE 2030.5 (Smart Energy Profile 2.0),
// the HTTPS/REST protocol between a utility server and distributed energy
// resources.
//
// IEEE 2030.5 mandates mutual TLS with the cipher suite
// TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 and ECDSA certificates. Without a
// device certificate a probe cannot read the data model, so detection
// examines the TLS layer: the fingerprinter completes a handshake far
// enough to see whether the server requests a client certificate and
// presents an ECDSA server certificate — the shape of an IEEE 2030.5
// server — then, if the handshake can be finished (an anonymous or
// misconfigured server), reads GET /dcap and recognises the DeviceCapability
// document and the urn:ieee:std:2030.5:ns namespace, which is conclusive.
//
// The probe reads the TLS layer directly: it sends its own TLS 1.2
// ClientHello offering CCM_8 (and common ECDHE suites) and parses the
// server's plaintext flight — the cipher suite chosen, the certificate's key
// type, and whether a client certificate is requested — without completing
// a handshake. A server choosing CCM_8, the IEEE 2030.5 suite that the Go
// standard library does not implement (GridAPPS-D offers only it), is
// recognised even though no Go TLS client could talk to it.
package ieee2030

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/httpx"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolIEEE2030_5

const namespace = "urn:ieee:std:2030.5:ns"

// Fingerprinter detects IEEE 2030.5.
type Fingerprinter struct{}

// New returns an IEEE 2030.5 fingerprinter.
func New() *Fingerprinter { return &Fingerprinter{} }

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{443, 8443, 8444, 8445, 4443},
		Priority:      120,
		Intrusiveness: core.Passive,
		Description:   "TLS 1.2 ClientHello offering CCM_8: chosen suite, certificate, client-certificate request; GET /dcap when a handshake completes",
	}
}

// Detect probes target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	b := fpx.New(proto)
	serverName := target.Host
	if target.TLS != nil && target.TLS.ServerName != "" {
		serverName = target.TLS.ServerName
	}

	// 1. A raw TLS 1.2 hello: the server's plaintext flight shows the suite
	// it chose, its certificate and whether it wants one from us.
	plain := target
	plain.TLS = nil
	s, err := wire.Dial(ctx, proto, plain, opts)
	if err != nil {
		return core.NoMatch(proto), err
	}
	fl, err := readFlight(s, serverName)
	trace := s.Exchanges()
	_ = s.Close()
	if err != nil && wire.IsTransport(err) && fl.suite == 0 {
		return b.Result("ieee2030.tls", "no TLS response", nil).WithExchanges(trace), err
	}
	f.scoreFlight(b, fl)

	// 2. When the server chose a suite crypto/tls implements, finish a
	// handshake (without a client certificate) and read /dcap: an
	// anonymous or misconfigured server answers it, which is conclusive.
	if fl.suite != 0 && fl.suite != suiteCCM8 {
		trace = append(trace, f.readDcap(ctx, b, target, serverName, fl.certRequested, opts)...)
	}
	if b.Confidence() < core.MatchThreshold {
		return b.Result("ieee2030.tls", "not IEEE 2030.5", nil).WithExchanges(trace), nil
	}
	details := "IEEE 2030.5 server"
	if !b.VariantSet() {
		details = "probable IEEE 2030.5 server (TLS only)"
	}
	return b.Result("ieee2030.tls", details, nil).WithExchanges(trace), nil
}

// scoreFlight scores the shape of the server's TLS flight.
func (f *Fingerprinter) scoreFlight(b *fpx.Builder, fl flight) {
	switch {
	case fl.suite == suiteCCM8:
		b.Score(core.ConfidenceHigh, "server selected TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, the IEEE 2030.5 cipher suite")
		b.Sig("tls", "ccm8")
	case fl.certRequested && fl.certECDSA:
		b.Score(core.ConfidenceHigh, "mutual-TLS server with an ECDSA certificate (IEEE 2030.5 shape)")
		b.Sig("tls", "mtls-ecdsa")
	case fl.certRequested:
		b.Score(core.ConfidenceMedium, "server requests a client certificate")
		b.Sig("tls", "mtls")
	case fl.certECDSA:
		b.Score(core.ConfidenceLow, "ECDSA TLS server (weak signal)")
	case fl.alert != 0:
		b.Evidence(fmt.Sprintf("TLS alert %d to a ClientHello offering CCM_8 and ECDHE suites", fl.alert))
	}
	if fl.suite == suiteCCM8 {
		if fl.certRequested {
			b.Evidence("server requests a client certificate")
		}
		if fl.certECDSA {
			b.Evidence("ECDSA server certificate")
		}
	}
	if fl.suite != 0 {
		b.Meta("cipherSuite", fmt.Sprintf("0x%04X", fl.suite))
	}
	if fl.subject != "" {
		b.Identity().Set("serverCertSubject", fl.subject)
	}
}

// readDcap completes a crypto/tls handshake without a client certificate
// and reads /dcap; it returns the trace.
func (f *Fingerprinter) readDcap(ctx context.Context, b *fpx.Builder, target core.Target, serverName string, certRequested bool, opts core.Options) []core.Exchange {
	d := net.Dialer{Timeout: target.EffectiveTimeout()}
	conn, err := d.DialContext(ctx, "tcp", target.Addr())
	if err != nil {
		return nil
	}
	defer conn.Close() //nolint:errcheck
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // fingerprinting identifies, it does not trust
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{}, nil // present no certificate
		},
	}
	if net.ParseIP(serverName) == nil {
		cfg.ServerName = serverName
	}
	tc := tls.Client(conn, cfg)
	hctx, cancel := context.WithTimeout(ctx, target.EffectiveTimeout())
	err = tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		b.Evidence("TLS handshake without a client certificate refused")
		return nil
	}
	ss := wire.Wrap(ctx, proto, target, tc, opts)
	resp, err := httpx.Request(ss, "dcap", "GET", target.Host, "/dcap", map[string]string{"Accept": "application/sep+xml"}, 8192)
	if err != nil {
		return ss.Exchanges()
	}
	body := string(resp.Body)
	switch {
	case strings.Contains(body, namespace) || strings.Contains(body, "DeviceCapability"):
		b.Score(core.ConfidenceCertain, "GET /dcap returned an IEEE 2030.5 DeviceCapability")
		b.Variant("IEEE 2030.5")
		b.Sig("dcap", "ok")
		parseDcap(b, body)
	case resp.Status == 403 && certRequested:
		b.Score(core.ConfidenceHigh, "server answers 403 without a client certificate (IEEE 2030.5 access control)")
		b.Sig("dcap", "403")
	}
	return ss.Exchanges()
}

func parseDcap(b *fpx.Builder, body string) {
	if i := strings.Index(body, "pollRate=\""); i >= 0 {
		rest := body[i+len("pollRate=\""):]
		if j := strings.IndexByte(rest, '"'); j > 0 {
			b.Identity().Set("pollRate", rest[:j])
		}
	}
	for _, link := range []string{"TimeLink", "EndDeviceListLink", "MirrorUsagePointListLink"} {
		if strings.Contains(body, link) {
			b.Evidence("DeviceCapability advertises " + link)
		}
	}
}
