// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// modbusServer answers FC43 like a Modbus device and returns its address.
func modbusServer(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 260)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				req := buf[:n]
				tid := binary.BigEndian.Uint16(req)
				// FC43/14 basic: vendor "Acme".
				pdu := []byte{0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x04, 'A', 'c', 'm', 'e'}
				resp := make([]byte, 7+len(pdu))
				binary.BigEndian.PutUint16(resp, tid)
				binary.BigEndian.PutUint16(resp[4:], uint16(1+len(pdu)))
				resp[6] = 1
				copy(resp[7:], pdu)
				_, _ = c.Write(resp)
			}()
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return h, n
}

func TestCLIDetectText(t *testing.T) {
	host, port := modbusServer(t)
	var out, errw bytes.Buffer
	code := run([]string{"detect", host + ":" + strconv.Itoa(port), "--protocol", "modbus", "--identify"}, &out, &errw)
	if code != exitDetected {
		t.Fatalf("code %d, stderr %s", code, errw.String())
	}
	if !strings.Contains(out.String(), "Modbus TCP") || !strings.Contains(out.String(), "Acme") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestCLIDetectJSON(t *testing.T) {
	host, port := modbusServer(t)
	var out, errw bytes.Buffer
	code := run([]string{"detect", host, "--port", strconv.Itoa(port), "--protocol", "modbus", "--format", "json", "--trace"}, &out, &errw)
	if code != exitDetected {
		t.Fatalf("code %d", code)
	}
	var doc struct {
		Best struct {
			Protocol string `json:"protocol"`
			Matched  bool   `json:"matched"`
		} `json:"best"`
		Results []struct {
			Exchanges []map[string]string `json:"exchanges"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if doc.Best.Protocol != "modbus" || !doc.Best.Matched {
		t.Fatalf("best %+v", doc.Best)
	}
	if len(doc.Results) == 0 || len(doc.Results[0].Exchanges) == 0 {
		t.Fatal("no trace in json")
	}
}

func TestCLIConnectionError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	var out, errw bytes.Buffer
	code := run([]string{"detect", addr, "--protocol", "modbus", "--timeout", "500ms"}, &out, &errw)
	if code != exitConnError {
		t.Fatalf("code %d (want %d)", code, exitConnError)
	}
}

func TestCLIBadArgs(t *testing.T) {
	var out, errw bytes.Buffer
	if run([]string{"detect", "127.0.0.1"}, &out, &errw) != exitBadParams {
		t.Fatal("missing port should be bad params")
	}
	errw.Reset()
	if run([]string{"detect", "127.0.0.1:1", "--protocol", "nope"}, &out, &errw) != exitBadParams {
		t.Fatal("bad protocol should be bad params")
	}
}

func TestCLINoMatch(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			_, _ = c.Read(make([]byte, 16))
			_ = c.Close() // close without answering
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var out, errw bytes.Buffer
	code := run([]string{"detect", "127.0.0.1:" + port, "--protocol", "modbus"}, &out, &errw)
	if code != exitNoMatch {
		t.Fatalf("code %d (want %d)", code, exitNoMatch)
	}
}

func TestCLIListAndVersion(t *testing.T) {
	var out, errw bytes.Buffer
	if run([]string{"list"}, &out, &errw) != 0 || !strings.Contains(out.String(), "modbus") {
		t.Fatalf("list:\n%s", out.String())
	}
	out.Reset()
	if run([]string{"version"}, &out, &errw) != 0 || !strings.Contains(out.String(), "otprobe") {
		t.Fatalf("version:\n%s", out.String())
	}
}

func TestParseTarget(t *testing.T) {
	f := detectFlags{timeout: time.Second}
	got, err := parseTarget("udp://10.0.0.5:47808", f)
	if err != nil || got.Network.String() != "udp" || got.Port != 47808 {
		t.Fatalf("udp: %+v %v", got, err)
	}
	got, err = parseTarget("tls://host:802", f)
	if err != nil || got.TLS == nil {
		t.Fatalf("tls: %+v %v", got, err)
	}
	got, err = parseTarget("10.0.0.5", detectFlags{port: 502, timeout: time.Second})
	if err != nil || got.Host != "10.0.0.5" || got.Port != 502 {
		t.Fatalf("bare + --port: %+v %v", got, err)
	}
	if _, err := parseTarget("10.0.0.5", f); err == nil {
		t.Fatal("no port should error")
	}
	if _, err := parseTarget("10.0.0.5:99999", f); err == nil {
		t.Fatal("bad port should error")
	}
	got, _ = parseTarget("10.0.0.5:502", detectFlags{useTLS: true, timeout: time.Second})
	if got.TLS == nil {
		t.Fatal("--tls should set a TLS config")
	}
}
