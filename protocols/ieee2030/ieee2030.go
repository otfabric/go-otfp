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
// Because the required CCM_8 cipher suite is not in the Go standard
// library, a server that offers only CCM_8 (such as GridAPPS-D) aborts the
// handshake with "no cipher suite in common"; that specific failure is
// itself a signal and is reported.
package ieee2030

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
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
		Description:   "TLS handshake (mutual-TLS request, ECDSA certificate, CCM_8); GET /dcap when the handshake completes",
	}
}

// Detect probes target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	b := fpx.New(proto)
	d := net.Dialer{Timeout: target.EffectiveTimeout()}
	conn, err := d.DialContext(ctx, "tcp", target.Addr())
	if err != nil {
		return core.NoMatch(proto), core.ClassifyDial(proto, target.Addr(), err)
	}
	defer conn.Close() //nolint:errcheck

	var (
		certRequested bool
		serverECDSA   bool
		serverSubject string
	)
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // fingerprinting identifies, it does not trust
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			certRequested = true
			return &tls.Certificate{}, nil // present no certificate
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) > 0 {
				if c, err := x509.ParseCertificate(rawCerts[0]); err == nil {
					_, serverECDSA = c.PublicKey.(*ecdsa.PublicKey)
					serverSubject = c.Subject.String()
				}
			}
			return nil
		},
	}
	if target.TLS != nil && target.TLS.ServerName != "" {
		cfg.ServerName = target.TLS.ServerName
	}

	tc := tls.Client(conn, cfg)
	hctx, cancel := context.WithTimeout(ctx, target.EffectiveTimeout())
	hsErr := tc.HandshakeContext(hctx)
	cancel()

	// Score the TLS shape first; it holds whether or not the handshake
	// then fails for lack of a client certificate.
	switch {
	case hsErr != nil && strings.Contains(hsErr.Error(), "no cipher suite in common"):
		b.Score(core.ConfidenceHigh, "TLS server offers only a cipher suite Go lacks (consistent with IEEE 2030.5 CCM_8-only)")
		b.Sig("tls", "ccm8-only")
	case certRequested && serverECDSA:
		b.Score(core.ConfidenceHigh, "mutual-TLS server with an ECDSA certificate (IEEE 2030.5 shape)")
		b.Sig("tls", "mtls-ecdsa")
	case certRequested:
		b.Score(core.ConfidenceMedium, "server requests a client certificate")
		b.Sig("tls", "mtls")
	case serverECDSA:
		b.Score(core.ConfidenceLow, "ECDSA TLS server (weak signal)")
	}
	if serverSubject != "" {
		b.Identity().Set("serverCertSubject", serverSubject)
	}

	// When the handshake completed (an anonymous or misconfigured server),
	// read /dcap for the conclusive DeviceCapability document.
	var trace []core.Exchange
	if hsErr == nil {
		// Over the established TLS connection: framed HTTP read, traced.
		ss := wire.Wrap(ctx, proto, target, tc, opts)
		resp, err := httpx.Request(ss, "dcap", "GET", target.Host, "/dcap", map[string]string{"Accept": "application/sep+xml"}, 8192)
		trace = ss.Exchanges()
		if err == nil {
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
		}
	}

	_ = tc.Close()
	if b.Confidence() < core.MatchThreshold {
		return b.Result("ieee2030.tls", "not IEEE 2030.5", nil).WithExchanges(trace), nil
	}
	details := "IEEE 2030.5 server"
	if !b.VariantSet() {
		details = "probable IEEE 2030.5 server (TLS only)"
	}
	return b.Result("ieee2030.tls", details, nil).WithExchanges(trace), nil
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
