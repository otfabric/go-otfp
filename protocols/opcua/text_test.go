// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// endpointDescription encodes one EndpointDescription with the fields the
// fingerprinter reads; everything else is null or empty.
func endpointDescription(appURI, productURI, appName, policy string) []byte {
	b := str(nil, "opc.tcp://server:4840")
	b = str(b, appURI)
	b = str(b, productURI)
	b = str(append(b, 0x02), appName) // LocalizedText: text only
	b = le32(b, 0)                    // application type
	b = str(b, "")                    // gateway server URI
	b = str(b, "")                    // discovery profile URI
	b = le32(b, 0)                    // discovery URLs
	b = str(b, "")                    // server certificate
	b = le32(b, 1)                    // security mode
	b = str(b, policy)
	b = le32(b, 0) // user identity tokens
	b = str(b, "") // transport profile URI
	return append(b, 0)
}

// endpointsReply is a GetEndpoints response carrying the descriptions.
func endpointsReply(eps ...[]byte) []byte {
	b := append(append(make([]byte, 16), fourByteNodeID(idGetEndpointsResponse)...), responseHeader(0)...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(eps)))
	for _, e := range eps {
		b = append(b, e...)
	}
	return message(msgMSG, b)
}

// The reason of a UACP ERR and the strings of GetEndpoints reach the result
// as text only, whatever the server put into them.
func TestServerStringsAreText(t *testing.T) {
	const nt = fuzzkit.NonText
	t.Run("ERR reason", func(t *testing.T) {
		body := str(le32(nil, 0x80830000), "wrong"+nt+" endpoint")
		target := testsrv.TCP(t, testsrv.Script(message(msgERR, body)))
		r, err := New().Detect(context.Background(), target, core.Options{})
		fuzzkit.Check(t, proto, r, err)
		want := "UACP ERR 0x80830000 (wrong endpoint): an OPC UA server rejecting the endpoint URL"
		if !r.Matched || len(r.Evidence) != 1 || r.Evidence[0] != want {
			t.Fatalf("evidence %q, want %q", r.Evidence, want)
		}
	})
	t.Run("ERR reason longer than the bound", func(t *testing.T) {
		body := str(le32(nil, 0x80830000), strings.Repeat("r", 100_000))
		target := testsrv.TCP(t, testsrv.Script(message(msgERR, body)))
		r, err := New().Detect(context.Background(), target, core.Options{})
		fuzzkit.Check(t, proto, r, err)
		if n := strings.Count(r.Evidence[0], "r"); n < fpx.MaxText || n > fpx.MaxText+16 {
			t.Fatalf("%d octets of the reason kept, want %d", n, fpx.MaxText)
		}
	})
	t.Run("GetEndpoints", func(t *testing.T) {
		ep := endpointDescription("urn:app"+nt, "urn:product"+nt, "name"+nt, "http://opcfoundation.org/UA/SecurityPolicy#Basic"+nt+"256")
		target := testsrv.TCP(t, testsrv.Script(ackFrame, opnReply, endpointsReply(ep)))
		r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
		fuzzkit.Check(t, proto, r, err)
		id := r.Identity
		if id == nil || id.Name != "name" || id.Attributes["applicationUri"] != "urn:app" ||
			id.Attributes["productUri"] != "urn:product" || id.Attributes["securityPolicies"] != "Basic256" {
			t.Fatalf("identity %+v", id)
		}
		if !strings.HasSuffix(r.Fingerprint.Signature, "policies=Basic256") {
			t.Fatalf("signature %q", r.Fingerprint.Signature)
		}
	})
}

// At most maxPolicies distinct security policies are kept.
func TestSecurityPoliciesBounded(t *testing.T) {
	for _, n := range []int{maxPolicies - 1, maxPolicies, maxPolicies + 1, maxEndpoints} {
		var eps [][]byte
		for i := range n {
			eps = append(eps, endpointDescription("urn:a", "urn:p", "n", fmt.Sprintf("urn:policy#P%d", i)))
		}
		target := testsrv.TCP(t, testsrv.Script(ackFrame, opnReply, endpointsReply(eps...)))
		r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
		fuzzkit.Check(t, proto, r, err)
		got := len(strings.Split(r.Identity.Attributes["securityPolicies"], ","))
		if want := min(n, maxPolicies); got != want {
			t.Errorf("%d endpoints with distinct policies: %d kept, want %d", n, got, want)
		}
	}
}
