// SPDX-License-Identifier: MIT

package ieee2030

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/otfabric/go-otfp/internal/wire"
)

// TLS constants of the hello probe.
const (
	suiteCCM8     = 0xC0AE // TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, mandated by IEEE 2030.5
	recHandshake  = 22
	recAlert      = 21
	hsServerHello = 2
	hsCertificate = 11
	hsCertRequest = 13
	hsHelloDone   = 14
	maxFlight     = 1 << 16
)

// offeredSuites: CCM_8 first, then common ECDHE suites a server that also
// speaks ordinary TLS may pick instead.
var offeredSuites = []uint16{
	suiteCCM8,
	0xC0AC, // TLS_ECDHE_ECDSA_WITH_AES_128_CCM
	0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	0x00FF, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
}

// flight is what a server's first TLS 1.2 flight reveals in plaintext.
type flight struct {
	suite         uint16 // the cipher suite the server chose; 0 when none
	certECDSA     bool   // the server certificate has an ECDSA key
	subject       string // the server certificate's subject
	certRequested bool   // a CertificateRequest: mutual TLS
	alert         byte   // the alert description, when the server refused
	done          bool   // ServerHelloDone seen
}

// maxServerName is the longest server_name sent: a DNS host name (RFC
// 1035) is at most 253 octets in text form. A longer name cannot be a
// host name and is left out rather than sent.
const maxServerName = 253

// clientHello builds a TLS 1.2 ClientHello offering CCM_8. TLS 1.3 is not
// offered: in TLS 1.2 the server's certificate and certificate request
// travel in plaintext, which is what the probe reads.
func clientHello(serverName string) []byte {
	var ext []byte
	if n := len(serverName); n > 0 && n <= maxServerName && net.ParseIP(serverName) == nil {
		name := binary.BigEndian.AppendUint16([]byte{0}, uint16(n))
		name = append(name, serverName...)
		list := binary.BigEndian.AppendUint16(nil, wire.Len16(len(name)))
		ext = appendExt(ext, 0x0000, append(list, name...)) // server_name
	}
	ext = appendExt(ext, 0x000a, []byte{0, 6, 0x00, 0x17, 0x00, 0x18, 0x00, 0x1d})             // supported_groups
	ext = appendExt(ext, 0x000b, []byte{1, 0})                                                 // ec_point_formats
	ext = appendExt(ext, 0x000d, []byte{0, 8, 0x04, 0x03, 0x05, 0x03, 0x08, 0x04, 0x04, 0x01}) // signature_algorithms
	ext = appendExt(ext, 0xff01, []byte{0})                                                    // renegotiation_info

	body := []byte{0x03, 0x03} // TLS 1.2
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	body = append(body, random...)
	body = append(body, 0) // session id
	body = binary.BigEndian.AppendUint16(body, wire.Len16(2*len(offeredSuites)))
	for _, s := range offeredSuites {
		body = binary.BigEndian.AppendUint16(body, s)
	}
	body = append(body, 1, 0) // compression: null
	body = binary.BigEndian.AppendUint16(body, wire.Len16(len(ext)))
	body = append(body, ext...)

	// Handshake length (24 bits) and record length: the hello is far
	// below both limits.
	hs := binary.BigEndian.AppendUint32(nil, uint32(wire.Len16(len(body))))
	hs[0] = 1 // client_hello, over the zero high octet
	hs = append(hs, body...)
	rec := binary.BigEndian.AppendUint16([]byte{recHandshake, 0x03, 0x01}, wire.Len16(len(hs)))
	return append(rec, hs...)
}

func appendExt(b []byte, typ uint16, data []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, wire.Len16(len(data)))
	return append(b, data...)
}

// recordFramer frames one TLS record.
var recordFramer = wire.FixedHeader(5, func(h []byte) int {
	if (h[0] != recHandshake && h[0] != recAlert) || h[1] != 0x03 {
		return -1
	}
	return 5 + int(binary.BigEndian.Uint16(h[3:5]))
})

// readFlight sends the ClientHello and parses the server's flight up to
// ServerHelloDone, an alert, or a read failure.
// Bounds of the server flight: a real one is a handful of records and a
// few kilobytes, so a peer that keeps sending records (or announces a
// huge handshake message) cannot hold the probe or grow its buffer.
const (
	maxRecords   = 64
	maxHandshake = 256 << 10
)

// errFlightTooLong reports a flight past maxRecords or maxHandshake.
var errFlightTooLong = errors.New("server flight exceeds the bounds of a TLS hello flight")

func readFlight(s *wire.Session, serverName string) (flight, error) {
	var f flight
	rec, err := s.RoundTrip("client-hello", clientHello(serverName), recordFramer, maxFlight)
	// The whole flight must arrive within two timeouts of the hello,
	// however the peer paces its records.
	deadline := time.Now().Add(2 * s.Timeout())
	var hs []byte // handshake bytes, reassembled across records
	for records := 1; err == nil; records++ {
		if len(rec) < 5 || (rec[0] != recHandshake && rec[0] != recAlert) {
			return f, fmt.Errorf("not a TLS record")
		}
		body := rec[5:]
		if rec[0] == recAlert {
			if len(body) >= 2 {
				f.alert = body[1]
			}
			return f, nil
		}
		hs = append(hs, body...)
		if hs, err = f.parse(hs); err != nil || f.done {
			return f, err
		}
		if records >= maxRecords || len(hs) > maxHandshake || !time.Now().Before(deadline) {
			return f, errFlightTooLong
		}
		rec, err = s.ReadUntil(recordFramer, maxFlight, deadline)
		if rec != nil {
			s.Record("server-flight", nil, rec)
		}
	}
	return f, err
}

func (f *flight) parse(hs []byte) ([]byte, error) {
	for len(hs) >= 4 {
		n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if len(hs) < 4+n {
			return hs, nil
		}
		msg := hs[4 : 4+n]
		switch hs[0] {
		case hsServerHello:
			// version(2) random(32) session id(1+n) cipher suite(2)
			if len(msg) < 35 || len(msg) < 35+int(msg[34])+2 {
				return nil, fmt.Errorf("short ServerHello")
			}
			f.suite = binary.BigEndian.Uint16(msg[35+int(msg[34]):])
		case hsCertificate:
			// certificates(3) { certificate(3) der }...
			if len(msg) >= 6 {
				m := int(msg[3])<<16 | int(msg[4])<<8 | int(msg[5])
				if 6+m <= len(msg) {
					if c, err := x509.ParseCertificate(msg[6 : 6+m]); err == nil {
						_, f.certECDSA = c.PublicKey.(*ecdsa.PublicKey)
						f.subject = c.Subject.String()
					}
				}
			}
		case hsCertRequest:
			f.certRequested = true
		case hsHelloDone:
			f.done = true
			return nil, nil
		}
		hs = hs[4+n:]
	}
	return hs, nil
}
