//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/protocols/canopen"
)

// The CANopenNode reference image of canopen-interop v0.3.1: canopend with
// its CiA 309-3 gateway, and canopend-device as a node on the same bus.
var (
	canopenImage = env("OTFP_CANOPEN_IMAGE", "ghcr.io/otfabric/canopen-interop-canopennode@sha256:1430fc9a54af9fc501cdb53fef9fd8cfc971fdc1470511e73dd49cd17ee6d67d")
	// nsenterImage creates vcan0 in the gateway's network namespace (the
	// CANopenNode image has no iproute2).
	nsenterImage = env("OTFP_NSENTER_IMAGE", "alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f")
)

// TestInteropCANopen runs the canopen fingerprinter against CANopenNode's
// canopend gateway (-c tcp-60000) with canopend-device as node 32 on a vcan
// interface. It needs a Docker host whose kernel has the vcan module
// (Linux with can, can-raw and vcan loaded; Docker Desktop has no CAN).
func TestInteropCANopen(t *testing.T) {
	if only := os.Getenv("OTFP_INTEROP_ADAPTERS"); only != "" && !strings.Contains(","+only+",", ",canopen-canopennode,") {
		t.Skip("not selected by OTFP_INTEROP_ADAPTERS")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		skipMissing(t, "docker not found")
	}
	hostPort := freePort(t)
	netns := docker(t, "run", "-d", "--rm", "-p", fmt.Sprintf("127.0.0.1:%d:60000/tcp", hostPort), "--entrypoint", "sleep", canopenImage, "infinity")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", netns).Run() })
	pid := docker(t, "inspect", "-f", "{{.State.Pid}}", netns)
	if out, err := exec.Command("docker", "run", "--rm", "--privileged", "--pid=host", nsenterImage,
		"nsenter", "-t", pid, "-n", "sh", "-c", "ip link add dev vcan0 type vcan && ip link set vcan0 up").CombinedOutput(); err != nil {
		skipMissing(t, "cannot create vcan0 (load can, can-raw, vcan on the Docker host): %v\n%s", err, out)
	}
	shared := "container:" + netns
	gw := docker(t, "run", "-d", "--rm", "--network", shared, "-w", "/tmp", "--entrypoint", "canopend", canopenImage, "vcan0", "-i", "127", "-c", "tcp-60000")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", gw).Run() })
	dev := docker(t, "run", "-d", "--rm", "--network", shared, "-w", "/tmp", "--entrypoint", "canopend-device", canopenImage, "vcan0", "-i", "32")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", dev).Run() })

	target := core.Target{Host: "127.0.0.1", Port: hostPort, Network: core.TCP, Timeout: 5 * time.Second}
	opts := core.Options{Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly}
	fp := canopen.NewWithConfig(canopen.Config{Node: 32})

	// docker's proxy accepts before canopend listens: retry until the
	// gateway answers.
	var res core.Result
	deadline := time.Now().Add(60 * time.Second)
	for {
		r, err := fp.Detect(context.Background(), target, opts)
		if err == nil && r.Matched {
			res = r
			break
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", gw).CombinedOutput()
			t.Fatalf("no CANopen gateway detected: %v (%v)\n%s", r, err, logs)
		}
		time.Sleep(time.Second)
	}
	if res.Protocol != core.ProtocolCANopen {
		t.Fatalf("protocol %s", res.Protocol)
	}
	if got := res.Identity.String(); !strings.Contains(got, "otfabric canopen-interop device") {
		t.Errorf("identity %q, want the canopend-device name", got)
	}
	t.Logf("canopen-canopennode -> %s", res)
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	var stderr strings.Builder
	cmd := exec.Command("docker", args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}
