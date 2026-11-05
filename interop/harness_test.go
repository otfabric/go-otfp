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
		image:    env("OTFP_MODBUS_IMAGE", "ghcr.io/otfabric/modbus-interop-pymodbus@sha256:dbd305a7789a0f1469d403a163ce463297cda77066bf4b1a14d7604031361e3b"),
		cmd:      []string{"server", "--fixture", "/fixtures/baseline/fixture.json"},
		identity: "otfabric",
	},
	{
		name: "dnp3-opendnp3", proto: core.ProtocolDNP3, port: 20000,
		image: env("OTFP_DNP3_IMAGE", "ghcr.io/otfabric/dnp3-interop-opendnp3@sha256:76a2baa2da118e049196d2b7310f84cc79b38ddf0443a40e410e4553f4773203"),
		cmd:   []string{"server", "--fixture", "/fixtures/baseline/fixture.json"},
	},
	{
		name: "iec104-lib60870", proto: core.ProtocolIEC104, port: 2404,
		image: env("OTFP_IEC104_IMAGE", "ghcr.io/otfabric/iec104-interop-lib60870@sha256:c1f0cc95e39316df8c182b887b933e0488c92845fedade00605aedc816a0af9a"),
		cmd:   []string{"server", "--fixture", "/fixtures/baseline/fixture.json"},
	},
	{
		name: "s7-snap7", proto: core.ProtocolS7, port: 102,
		image:     env("OTFP_S7_IMAGE", "ghcr.io/otfabric/snap7-interop-native@sha256:6b97b3233346323508c5c3caf7be3a151fa75ac017592d14919b7112efa46b88"),
		env:       map[string]string{"SNAP_INTEROP_FIXTURE": "/fixtures/basic-db.compiled.json", "SNAP_INTEROP_LISTEN_ADDRESS": "0.0.0.0", "SNAP_INTEROP_PORT": "102", "SNAP_INTEROP_STATE_PATH": "/tmp/state.json"},
		mountRepo: "snap7-interop/fixtures/compiled", mountAt: "/fixtures",
	},
	{
		name: "opcua-open62541", proto: core.ProtocolOPCUA, port: 4840,
		image:     env("OTFP_OPCUA_IMAGE", "ghcr.io/otfabric/opcua-interop-open62541@sha256:6e87e0a33ed42450b923eb5576f5e3b730c3c3cdd1c489ea7da9f197631a2441"),
		cmd:       []string{"server", "--fixture", "/fixtures/baseline/fixture.json", "--bind-address", "0.0.0.0", "--bind-port", "4840"},
		identity:  "OTFabric OPC UA Compatibility Server", // GetEndpoints decoded
		mountRepo: "opcua-interop/fixtures", mountAt: "/fixtures",
	},
	{
		name: "enip-opener", proto: core.ProtocolENIP, port: 44818,
		image:    env("OTFP_ENIP_IMAGE", "ghcr.io/otfabric/ethernetip-interop-opener@sha256:6dc59b7b846398575e1dabf57ed62d6c45ab165dc4804ae4fbe0d59e7fd4c1d2"),
		cmd:      []string{"server"},
		identity: "OpENer",
	},
	{
		name: "bacnet-stack", proto: core.ProtocolBACnet, port: 47808, udp: true,
		image:    env("OTFP_BACNET_IMAGE", "ghcr.io/otfabric/bacnet-interop-bacnet-stack@sha256:3a941e08fbe47cf6c7dfb2a8036b4902f824e8dd178dc7b2ff846942b72ad47a"),
		env:      map[string]string{"FIXTURE": "device-baseline-v2"},
		identity: "InteropDevice",
	},
	{
		name: "ocpp-mobilityhouse", proto: core.ProtocolOCPP, port: 9000,
		image:   env("OTFP_OCPP_IMAGE", "ghcr.io/otfabric/ocpp-interop-mobilityhouse@sha256:14d8da52ba062873fdc55834585dcd97b2405557004a3c438f04ee60e1bff1b5"),
		cmd:     []string{"server", "--version", "2.0.1"},
		variant: "OCPP",
		path:    "/ocpp/OT-FABRIC-TEST-001", // the fixture's known station
	},
	{
		// GridAPPS-D offers only CCM_8, which no Go TLS client can use: the
		// raw-hello probe still recognises it.
		name: "ieee2030-gridappsd", proto: core.ProtocolIEEE2030_5, port: 443, pki: true,
		image:    env("OTFP_IEEE2030_GRIDAPPSD_IMAGE", "ghcr.io/otfabric/ieee20305-interop-gridappsd@sha256:c72fbdb7c91fae1a59ee87938cc834651db2924317dd362814dc682d57a5b3af"),
		cmd:      []string{"server", "--version", "2018", "--tls-dir", "/tls/server"},
		identity: "CN=gridappsd-server",
	},
	{
		name: "ieee2030-envoy", proto: core.ProtocolIEEE2030_5, port: 443, pki: true,
		image:    env("OTFP_IEEE2030_ENVOY_IMAGE", "ghcr.io/otfabric/ieee20305-interop-envoy@sha256:850d16d293866fbd424716df6f3fb5ebb954a87616e10b082dbe5ea16c3f1bdb"),
		cmd:      []string{"server", "--version", "2018", "--tls-dir", "/tls/server"},
		identity: "CN=",
	},
	{
		name: "openadr-openleadr", proto: core.ProtocolOpenADR, port: 8080,
		image:     env("OTFP_OPENADR_IMAGE", "ghcr.io/otfabric/openadr-interop-openleadr@sha256:331f178d185537743fbda4b3d5cf9d03e629f41e5b1a7f0865ec1e07e6c7b3a3"),
		cmd:       []string{"server", "--fixture", "/fixtures/baseline/fixture.json"},
		variant:   "OpenADR",
		publicURL: true,
	},
}

// skipMissing skips for a missing prerequisite, or fails when
// OTFP_REQUIRE_INTEROP=1: the nightly job sets it, so a broken checkout or
// PKI cannot pass as a run of skips.
func skipMissing(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("OTFP_REQUIRE_INTEROP") == "1" {
		t.Fatalf("OTFP_REQUIRE_INTEROP=1: "+format, args...)
	}
	t.Skipf(format, args...)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func TestInterop(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		skipMissing(t, "docker not found")
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
			skipMissing(t, "sibling fixtures %s not found (checkout %s beside go-otfp)", dir, a.mountRepo)
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
	// Stdout only: on a first run stderr carries the pull progress, which
	// is not part of the container ID.
	var stderr strings.Builder
	run := exec.Command("docker", args...)
	run.Stderr = &stderr
	out, err := run.Output()
	if err != nil {
		t.Fatalf("docker run %s: %v\n%s", a.name, err, stderr.String())
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
		skipMissing(t, "ieee20305-interop not checked out beside go-otfp: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "tls")
	cmd := exec.Command("bash", "-c", `source scripts/lib.sh && make_pki "$0" "$(jq -r .device.serial fixtures/baseline/fixture.json)" gridappsd-server envoy-server localhost 127.0.0.1 -- localhost`, dir)
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		skipMissing(t, "make_pki (needs bash, jq, openssl): %v\n%s", err, out)
	}
	return dir
}
