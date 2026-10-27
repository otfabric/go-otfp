//go:build interop

// SPDX-License-Identifier: MIT

// Package interop runs the go-otfp fingerprinters against the reference
// servers of the otfabric *-interop container suites and checks that each
// endpoint is detected as the protocol it speaks. It is gated behind the
// `interop` build tag and needs Docker; run it with `make interop`.
//
// The images are the published, multi-arch reference servers that the
// sibling go-<protocol> libraries qualify against, pinned here by digest.
// Images that are not published (GPL reference stacks such as the DNP3
// stepfunc server and the PROFINET p-net device) and servers that need host
// Layer-2 access (PROFINET DCP) are out of scope for this suite.
package interop

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
)

// adapter is one reference server container.
type adapter struct {
	name    string
	image   string
	cmd     []string          // container command / arguments
	env     map[string]string // environment variables
	port    int               // container port to detect on
	udp     bool
	proto   core.Protocol
	variant string // optional substring expected in the best result's variant
	// identity, when set, must appear in the detected identity's one-line
	// string (identify mode).
	identity string
	// publicURL, when true, passes --public-url http://127.0.0.1:<host>
	// (OpenADR needs its externally reachable URL).
	publicURL bool
	// mountRepo and mountAt mount a sibling *-interop repo's fixtures into
	// the container (for images that do not bake them). The adapter is
	// skipped when the sibling repo is not checked out beside go-otfp.
	mountRepo, mountAt string
	// path overrides the HTTP/WebSocket path (OCPP needs a known station id).
	path string
	// pki, when set, generates the IEEE 2030.5 throwaway PKI with the
	// sibling ieee20305-interop's helper and mounts it at /tls.
	pki bool
}

// adapters are pinned to otfabric interop releases; see each go-<protocol>
// library's interop harness for the source of the digests.
var adapters = []adapter{
	{
		name: "modbus-pymodbus", proto: core.ProtocolModbus, port: 1502,
		image:    env("OTFP_MODBUS_IMAGE", "ghcr.io/otfabric/modbus-interop-pymodbus@sha256:33b703491abc2f15c229ff433ffbb79eb00e86a8c56c30fb7799c8ed13832f5a"),
		cmd:      []string{"server", "--fixture", "/fixtures/baseline/fixture.json"},
		identity: "otfabric",
	},
	{
		name: "dnp3-opendnp3", proto: core.ProtocolDNP3, port: 20000,
		image: env("OTFP_DNP3_IMAGE", "ghcr.io/otfabric/dnp3-interop-opendnp3@sha256:abc0d87ef30aceff748cc513f1e5840618ea9a78cc8a4713ba67d06507089314"),
		cmd:   []string{"server", "--fixture", "/fixtures/baseline/fixture.json"},
	},
	{
		name: "iec104-lib60870", proto: core.ProtocolIEC104, port: 2404,
		image: env("OTFP_IEC104_IMAGE", "ghcr.io/otfabric/iec104-interop-lib60870@sha256:c2f6df54d5b0bdda0411db7ad601b77e320d8d628e6988cd1c7d507f4e56ba72"),
		cmd:   []string{"server", "--fixture", "/fixtures/baseline/fixture.json"},
	},
	{
		name: "s7-snap7", proto: core.ProtocolS7, port: 102,
		image:     env("OTFP_S7_IMAGE", "ghcr.io/otfabric/snap7-interop-native@sha256:66e3826813005bfacb8510ce5de33119315499325b35bf616dcf61de0506a342"),
		env:       map[string]string{"SNAP_INTEROP_FIXTURE": "/fixtures/basic-db.compiled.json", "SNAP_INTEROP_LISTEN_ADDRESS": "0.0.0.0", "SNAP_INTEROP_PORT": "102", "SNAP_INTEROP_STATE_PATH": "/tmp/state.json"},
		mountRepo: "snap7-interop/fixtures/compiled", mountAt: "/fixtures",
	},
	{
		name: "opcua-open62541", proto: core.ProtocolOPCUA, port: 4840,
		image:     env("OTFP_OPCUA_IMAGE", "ghcr.io/otfabric/opcua-interop-open62541@sha256:ff00dd63217f42c68e5233563d3d0b75290838f4d01e866fe1f9e1c730adcdbc"),
		cmd:       []string{"server", "--fixture", "/fixtures/baseline/fixture.json", "--bind-address", "0.0.0.0", "--bind-port", "4840"},
		identity:  "OTFabric OPC UA Compatibility Server", // GetEndpoints decoded
		mountRepo: "opcua-interop/fixtures", mountAt: "/fixtures",
	},
	{
		name: "enip-opener", proto: core.ProtocolENIP, port: 44818,
		image:    env("OTFP_ENIP_IMAGE", "ghcr.io/otfabric/ethernetip-interop-opener@sha256:bf7c3d9078cef6299c90c12a8460437fdd85a041ef2e227133609c3ad0a45526"),
		cmd:      []string{"server"},
		identity: "OpENer",
	},
	{
		name: "bacnet-stack", proto: core.ProtocolBACnet, port: 47808, udp: true,
		image:    env("OTFP_BACNET_IMAGE", "ghcr.io/otfabric/bacnet-interop-bacnet-stack@sha256:78d21078ea8b5444e346ca6ee23aa0b1539ee8f036d759fea1f0fdbea35c0d30"),
		env:      map[string]string{"FIXTURE": "device-baseline-v2"},
		identity: "InteropDevice",
	},
	{
		name: "ocpp-mobilityhouse", proto: core.ProtocolOCPP, port: 9000,
		image:   env("OTFP_OCPP_IMAGE", "ghcr.io/otfabric/ocpp-interop-mobilityhouse@sha256:3f14958e9f21d85d3e18542bcbc9460bc8b7163a2982f4539dc7b8f78eb70fca"),
		cmd:     []string{"server", "--version", "2.0.1"},
		variant: "OCPP",
		path:    "/ocpp/OT-FABRIC-TEST-001", // the fixture's known station
	},
	{
		// GridAPPS-D offers only CCM_8, which no Go TLS client can use: the
		// raw-hello probe still recognises it.
		name: "ieee2030-gridappsd", proto: core.ProtocolIEEE2030_5, port: 443, pki: true,
		image:    env("OTFP_IEEE2030_GRIDAPPSD_IMAGE", "ghcr.io/otfabric/ieee20305-interop-gridappsd@sha256:7b04e6c482df6536d15ba06e17e4c317a68031cabeed54cc03bc5b395f5b8d68"),
		cmd:      []string{"server", "--version", "2018", "--tls-dir", "/tls/server"},
		identity: "CN=gridappsd-server",
	},
	{
		name: "ieee2030-envoy", proto: core.ProtocolIEEE2030_5, port: 443, pki: true,
		image:    env("OTFP_IEEE2030_ENVOY_IMAGE", "ghcr.io/otfabric/ieee20305-interop-envoy@sha256:2dd3587071de81d7b96a7dbf65bf414a06a643a32f5d785b42ba7ebb0cb04d2d"),
		cmd:      []string{"server", "--version", "2018", "--tls-dir", "/tls/server"},
		identity: "CN=",
	},
	{
		name: "openadr-openleadr", proto: core.ProtocolOpenADR, port: 8080,
		image:     env("OTFP_OPENADR_IMAGE", "ghcr.io/otfabric/openadr-interop-openleadr@sha256:b8221b89983a5b7cdc69cea92443e05416336ad1ddcd843250770d65950b4fb2"),
		cmd:       []string{"server", "--fixture", "/fixtures/baseline/fixture.json"},
		variant:   "OpenADR",
		publicURL: true,
	},
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func TestInterop(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found")
	}
	only := os.Getenv("OTFP_INTEROP_ADAPTERS")
	for _, a := range adapters {
		if only != "" && !strings.Contains(","+only+",", ","+a.name+",") {
			continue
		}
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()
			host := startContainer(t, a)
			target := core.Target{Host: "127.0.0.1", Port: host, Network: network(a), Timeout: 5 * time.Second, Path: a.path}

			// Validate the adapter's own fingerprinter against its server.
			// The scan is restricted to that protocol (and the one it
			// refines) so that the earlier, malformed probes of a full
			// multi-protocol sweep cannot disturb a single-protocol
			// reference server before its own probe runs.
			protocols := []core.Protocol{a.proto}
			if a.proto == core.ProtocolSunSpec {
				protocols = append(protocols, core.ProtocolModbus)
			}
			report, err := otfp.NewEngine(core.EngineConfig{Mode: core.ModeIdentify, Protocols: protocols, MaxIntrusiveness: core.ReadOnly}).Scan(context.Background(), target)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if !report.Best.Matched || report.Best.Protocol != a.proto {
				t.Fatalf("detected %s (conf %.2f), want %s\nresults: %v", report.Best.Protocol, report.Best.Confidence, a.proto, report.Results)
			}
			if a.variant != "" && !strings.Contains(report.Best.Variant, a.variant) {
				t.Errorf("variant %q, want substring %q", report.Best.Variant, a.variant)
			}
			if a.identity != "" {
				if got := report.Best.Identity.String(); !strings.Contains(got, a.identity) {
					t.Errorf("identity %q, want substring %q", got, a.identity)
				}
			}
			t.Logf("%s -> %s", a.name, report.Best)
		})
	}
}

func network(a adapter) core.Network {
	if a.udp {
		return core.UDP
	}
	return core.TCP
}

// startContainer runs the adapter, maps its port to a loopback host port,
// waits for the port to accept, and returns the host port.
func startContainer(t *testing.T, a adapter) int {
	t.Helper()
	hostPort := freePort(t)
	proto := "tcp"
	if a.udp {
		proto = "udp"
	}
	args := []string{"run", "-d", "--rm", "-p", fmt.Sprintf("127.0.0.1:%d:%d/%s", hostPort, a.port, proto)}
	if a.proto == core.ProtocolS7 {
		args = append(args, "--cap-add", "NET_BIND_SERVICE")
	}
	if a.mountRepo != "" {
		dir := filepath.Join("..", "..", a.mountRepo)
		if _, err := os.Stat(dir); err != nil {
			t.Skipf("sibling fixtures %s not found (checkout %s beside go-otfp)", dir, a.mountRepo)
		}
		abs, _ := filepath.Abs(dir)
		args = append(args, "-v", abs+":"+a.mountAt+":ro")
	}
	if a.pki {
		args = append(args, "-v", makePKI(t)+":/tls:ro")
	}
	for k, v := range a.env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, a.image)
	args = append(args, a.cmd...)
	if a.publicURL {
		args = append(args, "--public-url", fmt.Sprintf("http://127.0.0.1:%d", hostPort))
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run %s: %v\n%s", a.name, err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })

	// Wait for the container's own readiness signal. Every otfabric interop
	// image prints a JSON ready event on stdout once its socket is bound
	// ("ready"/"server_ready"); a published port alone is not enough, since
	// docker's proxy accepts connections before the server binds.
	started := time.Now()
	deadline := started.Add(90 * time.Second)
	for time.Now().Before(deadline) {
		logs, _ := exec.Command("docker", "logs", id).CombinedOutput()
		if strings.Contains(string(logs), `ready"`) {
			time.Sleep(500 * time.Millisecond)
			return hostPort
		}
		if !a.udp && time.Since(started) > 30*time.Second && portOpen(hostPort) {
			// No ready line after a long wait, but the port answers: an
			// image without the readiness contract. (Before that, an open
			// port proves nothing: docker's proxy accepts at once.)
			return hostPort
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", id).CombinedOutput()
	t.Fatalf("%s did not become ready\n%s", a.name, logs)
	return 0
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return p
}

func portOpen(port int) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// makePKI writes the IEEE 2030.5 throwaway PKI with ieee20305-interop's own
// helper (scripts/lib.sh make_pki), and skips when that repository is not
// checked out beside go-otfp.
func makePKI(t *testing.T) string {
	t.Helper()
	repo, _ := filepath.Abs(filepath.Join("..", "..", "ieee20305-interop"))
	if _, err := os.Stat(filepath.Join(repo, "scripts", "lib.sh")); err != nil {
		t.Skipf("ieee20305-interop not checked out beside go-otfp: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "tls")
	cmd := exec.Command("bash", "-c", `source scripts/lib.sh && make_pki "$0" "$(jq -r .device.serial fixtures/baseline/fixture.json)" gridappsd-server envoy-server localhost 127.0.0.1 -- localhost`, dir)
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("make_pki (needs bash, jq, openssl): %v\n%s", err, out)
	}
	return dir
}
