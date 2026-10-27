// SPDX-License-Identifier: MIT

// Package ocpp fingerprints OCPP, the Open Charge Point Protocol spoken
// between electric-vehicle chargers and a charging station management
// system (CSMS) over WebSocket.
//
// Detection opens a WebSocket upgrade to a charger path, offering the
// subprotocols ocpp2.1, ocpp2.0.1 and ocpp1.6. A CSMS completes the
// handshake (HTTP 101) and echoes the OCPP subprotocol it selected, which
// identifies both OCPP and the version negotiated; the connection is then
// closed without a BootNotification. A 401 with the OCPP Basic realm, or a
// 404 for an unknown charge-point identity, are weaker but characteristic
// signals.
//
// Detect and identify behave the same: OCPP exposes no device identity
// before the charger sends a BootNotification, which only the charger may
// do. Run the fingerprinter over a TLS target (wss://) for secured CSMSs.
package ocpp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"context"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/httpx"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolOCPP

// subprotocols are offered most-recent first, as a charger would.
const subprotocols = "ocpp2.1, ocpp2.0.1, ocpp1.6"

// Config configures the fingerprinter.
type Config struct {
	// Path is the WebSocket path. The default is /ocpp/<random id>, which
	// go-ocpp and most CSMSs require (the station identity is the last
	// segment).
	Path string
}

// Fingerprinter detects OCPP.
type Fingerprinter struct {
	path string
}

// New returns an OCPP fingerprinter.
func New() *Fingerprinter { return NewWithConfig(Config{}) }

// NewWithConfig returns a fingerprinter with the given configuration.
func NewWithConfig(c Config) *Fingerprinter { return &Fingerprinter{path: c.Path} }

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{80, 443, 8080, 9000, 8887},
		Priority:      110,
		Intrusiveness: core.Passive,
		Description:   "WebSocket upgrade offering ocpp2.1/2.0.1/1.6; reads the selected subprotocol",
	}
}

// Detect probes target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	b := fpx.New(proto)
	s, err := wire.Dial(ctx, proto, target, opts)
	if err != nil {
		return core.NoMatch(proto), err
	}
	defer s.Close() //nolint:errcheck

	path := f.path
	if path == "" {
		path = "/ocpp/" + stationID()
	}
	host := hostHeader(target)
	var key [16]byte
	_, _ = rand.Read(key[:])
	resp, err := httpx.Request(s, "ws-upgrade", "GET", host, path, map[string]string{
		"Connection":             "Upgrade",
		"Upgrade":                "websocket",
		"Sec-WebSocket-Version":  "13",
		"Sec-WebSocket-Key":      base64.StdEncoding.EncodeToString(key[:]),
		"Sec-WebSocket-Protocol": subprotocols,
	}, 4096)
	if err != nil {
		if b.Confidence() == 0 {
			return b.Result("ocpp.ws", "no HTTP response", s), err
		}
		return b.Result("ocpp.ws", "no OCPP response", s), nil
	}

	switch resp.Status {
	case 101:
		if p := resp.WebSocketProtocol; isOCPP(p) {
			b.Score(core.ConfidenceCertain, "WebSocket upgrade accepted with OCPP subprotocol "+p)
			b.Variant(versionName(p))
			b.Sig("subprotocol", p)
			b.Meta("subprotocol", p)
			b.Identity().Set("ocppVersion", strings.TrimPrefix(p, "ocpp"))
		} else {
			// A CSMS with no supported subprotocol completes 101 then
			// closes with 1008 (go-ocpp); an unrelated server echoes
			// nothing.
			b.Score(core.ConfidenceMedium, "WebSocket upgrade accepted without an OCPP subprotocol")
			b.Sig("subprotocol", "none")
		}
	case 401:
		if realm := resp.Header.Get("WWW-Authenticate"); strings.Contains(strings.ToUpper(realm), `REALM="OCPP"`) {
			b.Score(core.ConfidenceHigh, `401 with the OCPP Basic realm`)
			b.Sig("auth", "ocpp-realm")
		} else {
			b.Score(core.ConfidenceLow, "WebSocket endpoint requires authentication")
		}
	case 404:
		b.Score(core.ConfidenceLow, "404: possibly a CSMS rejecting an unknown charge-point identity")
	default:
		b.Score(core.ConfidenceLow, fmt.Sprintf("HTTP %d to a WebSocket upgrade", resp.Status))
	}
	details := "not OCPP"
	if b.Confidence() >= core.MatchThreshold {
		details = "OCPP CSMS"
	}
	return b.Result("ocpp.ws", details, s), nil
}

func isOCPP(p string) bool {
	switch p {
	case "ocpp1.6", "ocpp2.0.1", "ocpp2.1":
		return true
	}
	return false
}

func versionName(p string) string {
	switch p {
	case "ocpp1.6":
		return "OCPP 1.6"
	case "ocpp2.0.1":
		return "OCPP 2.0.1"
	case "ocpp2.1":
		return "OCPP 2.1"
	}
	return ""
}

func hostHeader(t core.Target) string {
	if t.Port == 80 || t.Port == 443 {
		return t.Host
	}
	return t.Addr()
}

const idAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"

func stationID() string {
	var raw [8]byte
	_, _ = rand.Read(raw[:])
	b := make([]byte, 8)
	for i, c := range raw {
		b[i] = idAlphabet[int(c)%len(idAlphabet)]
	}
	return "OTFP-" + string(b)
}
