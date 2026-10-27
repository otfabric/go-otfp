// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/mbap"
	"github.com/otfabric/go-otfp/internal/testsrv"
	"github.com/otfabric/go-otfp/protocols/dnp3"
)

// exec runs the CLI and returns the exit code, stdout and stderr.
func exec(args ...string) (int, string, string) {
	var out, errw bytes.Buffer
	code := run(args, &out, &errw)
	return code, out.String(), errw.String()
}

func addr(t core.Target) string { return t.Addr() }

// modbus answers Read Device Identification with vendor "Acme".
func modbus(t *testing.T) core.Target {
	return testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		if len(req) < 10 {
			return nil, true
		}
		tid := uint16(req[0])<<8 | uint16(req[1])
		return mbap.Request(tid, req[6], 0x2B, 0x0E, req[9], 0x01, 0, 0, 1, 0, 4, 'A', 'c', 'm', 'e'), false
	})
}

func TestExitCodes(t *testing.T) {
	silent := testsrv.TCP(t, testsrv.Script())
	closer := testsrv.TCP(t, func([]byte) ([]byte, bool) { return nil, true })
	// A valid DNP3 frame that is not a link status: matched at medium.
	dnp := testsrv.TCP(t, testsrv.Script(dnp3.Frame(0x00, 1, 10, nil)))

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"detected", []string{"detect", addr(modbus(t)), "--protocol", "modbus"}, exitDetected},
		{"no match", []string{"detect", addr(closer), "--protocol", "modbus"}, exitNoMatch},
		{"partial", []string{"detect", addr(dnp), "--protocol", "dnp3", "-t", "300ms"}, exitPartial},
		{"refused", []string{"detect", addr(testsrv.Closed(t)), "--protocol", "modbus"}, exitTransport},
		{"timeout", []string{"detect", addr(silent), "--protocol", "modbus", "-t", "200ms"}, exitTimeout},
		{"unknown flag", []string{"detect", "x:1", "--bogus"}, exitUsage},
		{"missing target", []string{"detect"}, exitUsage},
		{"unknown command", []string{"probe"}, exitUsage},
		{"bad protocol", []string{"detect", "127.0.0.1:1", "--protocol", "nope"}, exitInvalidInput},
		{"bad format", []string{"detect", "127.0.0.1:1", "--format", "xml"}, exitInvalidInput},
		{"bad port", []string{"detect", "127.0.0.1:99999"}, exitInvalidInput},
		{"tls over udp", []string{"detect", "udp://127.0.0.1:47808", "--tls"}, exitInvalidInput},
		{"port and ports", []string{"detect", "127.0.0.1", "--port", "1", "--ports", "2"}, exitInvalidInput},
		{"conc without parallel", []string{"detect", "127.0.0.1:1", "--max-concurrency", "2"}, exitInvalidInput},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code, out, errw := exec(c.args...); code != c.want {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, c.want, out, errw)
			}
		})
	}
}

func TestTextOutput(t *testing.T) {
	code, out, _ := exec("detect", addr(modbus(t)), "--protocol", "modbus", "--identify")
	if code != exitDetected {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"Detected: Modbus TCP, confidence 1.00", "vendor       Acme", "fingerprint  modbus.fc43:", "1 probe in"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestJSONDocument(t *testing.T) {
	_, out, _ := exec("detect", addr(modbus(t)), "--protocol", "modbus", "-o", "json", "--trace")
	var doc struct {
		SchemaVersion int `json:"schemaVersion"`
		Scans         []struct {
			Port     int `json:"port"`
			Detected *struct {
				Protocol string         `json:"protocol"`
				Identity map[string]any `json:"identity"`
			} `json:"detected"`
			Results []struct {
				Exchanges []map[string]string `json:"exchanges"`
			} `json:"results"`
		} `json:"scans"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if doc.SchemaVersion != 1 || len(doc.Scans) != 1 || doc.Scans[0].Detected == nil || doc.Scans[0].Detected.Protocol != "modbus" {
		t.Fatalf("%s", out)
	}
	if len(doc.Scans[0].Results[0].Exchanges) == 0 {
		t.Fatal("--trace adds the exchanges")
	}
}

// With --format json even a usage error is one JSON object on stdout, and
// nothing goes to stderr.
func TestJSONErrors(t *testing.T) {
	for args, want := range map[string]string{
		"detect x:1 --bogus --format json":             "usage",
		"detect 127.0.0.1:1 --protocol nope -o json":   "invalid_input",
		"detect 127.0.0.1:1 --format=json --timeout 0": "invalid_input",
	} {
		_, out, errw := exec(strings.Fields(args)...)
		var doc struct {
			Error struct{ Kind, Code, Message string } `json:"error"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Error.Kind != want || doc.Error.Message == "" || errw != "" {
			t.Errorf("%s: stdout %q stderr %q", args, out, errw)
		}
	}
	// The env var selects JSON too.
	t.Setenv(formatEnv, "json")
	if _, out, _ := exec("detect", "--nope"); !strings.Contains(out, `"kind": "usage"`) {
		t.Errorf("env format: %q", out)
	}
}

func TestSweep(t *testing.T) {
	dev, closed := modbus(t), testsrv.Closed(t)
	code, out, _ := exec("detect", "127.0.0.1", "--ports", fmt.Sprintf("%d,%d", closed.Port, dev.Port), "--protocol", "modbus")
	if code != exitDetected || !strings.Contains(out, "Detected: Modbus TCP") || !strings.Contains(out, fmt.Sprintf("Closed:   %d", closed.Port)) {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// Completion: flag names and flag values, through cobra's __complete.
func TestCompletion(t *testing.T) {
	cases := map[string][]string{
		"__complete detect 1.2.3.4:5 --protocol mo":     {"modbus\tModbus TCP"},
		"__complete detect 1.2.3.4:5 --exclude modbus,": {"modbus,s7comm\tSiemens S7comm"},
		"__complete detect 1.2.3.4:5 --format ":         {"text", "json", "table"},
		"__complete detect 1.2.3.4:5 --network ":        {"udp\tUDP datagrams"},
		"__complete detect 1.2.3.4:5 --ports ":          {"502\tmodbus, sunspec"},
		"__complete detect ":                            {"udp://\t"},
		"__complete detect 1.2.3.4:5 --ide":             {"--identify"},
		"__complete completion ":                        {"bash", "zsh", "fish", "powershell"},
		"__complete ":                                   {"detect", "list", "version", "completion"},
	}
	for line, wants := range cases {
		args := strings.Split(line, " ")
		_, out, _ := exec(args...)
		for _, w := range wants {
			if !strings.Contains(out, w) {
				t.Errorf("%q: missing %q in\n%s", line, w, out)
			}
		}
	}
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		if code, out, _ := exec("completion", sh); code != 0 || len(out) < 500 {
			t.Errorf("completion %s: exit %d, %d bytes", sh, code, len(out))
		}
	}
}

func TestListAndVersion(t *testing.T) {
	_, out, _ := exec("list", "--format", "json")
	var l struct {
		Protocols []struct{ Protocol, Network string }
	}
	if json.Unmarshal([]byte(out), &l) != nil || len(l.Protocols) != len(core.AllProtocols())+1 {
		t.Fatalf("list json: %s", out)
	}
	for _, f := range []string{"text", "table"} {
		if code, out, _ := exec("list", "-o", f); code != 0 || !strings.Contains(out, "sunspec") {
			t.Errorf("list %s: %d %s", f, code, out)
		}
	}
	_, out, _ = exec("version", "-o", "json")
	var v map[string]string
	if json.Unmarshal([]byte(out), &v) != nil || v["version"] == "" || v["go"] == "" {
		t.Fatalf("version json: %s", out)
	}
}

func TestParseTargets(t *testing.T) {
	f := detectFlags{timeout: core.DefaultTimeout}
	ts, sweep, err := parseTargets("udp://10.0.0.5:47808", f)
	if err != nil || sweep || ts[0].Network != core.UDP {
		t.Fatalf("%v %v %v", ts, sweep, err)
	}
	ts, sweep, err = parseTargets("[::1]", f)
	if err != nil || !sweep || ts[0].Host != "::1" || len(ts) < 10 {
		t.Fatalf("bare v6 sweeps the well-known ports: %v %v", len(ts), err)
	}
	f.protocols = []string{"bacnet"}
	f.network = "udp"
	ts, _, _ = parseTargets("10.0.0.5", f)
	if len(ts) == 0 || ts[0].Port != 47808 {
		t.Fatalf("bacnet sweep %v", ts)
	}
}
