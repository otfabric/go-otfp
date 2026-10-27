# go-otfp — OT protocol fingerprinting

[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/otfabric/go-otfp.svg)](https://pkg.go.dev/github.com/otfabric/go-otfp)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/otfabric/go-otfp/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/go-otfp/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/otfabric/go-otfp/graph/badge.svg)](https://codecov.io/gh/otfabric/go-otfp)
[![Release](https://img.shields.io/github/v/release/otfabric/go-otfp?label=release)](https://github.com/otfabric/go-otfp/releases)

A pure-Go library and CLI that identify which operational-technology (OT)
protocol a network endpoint speaks, using **safe, connection-level probes**.
For each protocol it exchanges the standard handshake or a single harmless
request and judges the reply — it never writes a value, issues a control, or
changes a device's configuration. In **identify** mode it additionally sends
each protocol's standard read-only identity request and reports the vendor,
model, version and serial the device returns.

> **Stability:** this module is pre-1.0 (`v0.x`). Public APIs may change
> between minor tags; pin a version and read [RELEASE.md](RELEASE.md) before
> upgrading.

## Supported protocols

| Protocol | Transport | Default ports | Detection probe | Identity (identify mode) |
|---|---|---|---|---|
| **Modbus TCP** | TCP | 502 | Read Device Identification (FC 43/14) | vendor, product, version, model |
| **SunSpec** | TCP | 502 | `SunS` marker at 40000/0/50000 (refines Modbus) | manufacturer, model, version, serial, model chain |
| **IEC 61850 MMS** | TCP | 102 | COTP CR + session/ACSE/MMS Initiate | MMS Identify: vendor, model, revision |
| **Siemens S7comm / S7comm-plus** | TCP | 102 | COTP CR + S7 Setup Communication | SZL 0x0011/0x001C: order no., module, plant, serial |
| **OPC UA** (binary) | TCP | 4840 | UACP HEL/ACK handshake | GetEndpoints: application name, URIs, policies |
| **EtherNet/IP** (CIP) | TCP + UDP | 44818 | ListIdentity (0x0063) | vendor, device type, product, revision, serial |
| **BACnet/IP** | UDP | 47808 | confirmed ReadProperty of the device object | vendor, model, firmware, object name |
| **PROFINET IO** | UDP | 34964 | DCE/RPC ReadImplicit of I&M0 | vendor ID, order ID, serial, revisions |
| **DNP3** | TCP | 20000 | data-link REQUEST_LINK_STATUS | device attributes (g0): vendor, product, version |
| **IEC 60870-5-104** | TCP | 2404 | APCI TESTFR act/con | common address, ASDU types |
| **OCPP** | TCP (ws) | 80/443 | WebSocket upgrade (ocpp2.1/2.0.1/1.6) | negotiated version |
| **IEEE 2030.5** | TCP (TLS) | 443 | mutual-TLS / ECDSA / CCM_8 shape, GET /dcap | server certificate, poll rate |
| **OpenADR** (3 / 2.0b) | TCP | 8080/443 | GET /auth/server, /programs; oadrQueryRegistration | OAuth2 token URL |
| **CAN** (TCP gateway) | TCP | gateway-specific | SLCAN `V`/`N` commands | firmware version, serial |

Detection is **port-agnostic**: the engine tries the fingerprinters of the
target's port first, then the rest, so a protocol on a non-standard port is
still found. See [FINGERPRINTS.md](FINGERPRINTS.md) for the probe bytes, the
confidence model and the standards behind each detector.

## Key principles

- **Connection-level only** — a handshake or one safe request per protocol;
  no register writes, no control commands, no configuration changes.
- **Read-only identity** — identify mode uses each protocol's own standard
  identification service (Read Device Identification, the CIP Identity
  object, SZL, MMS Identify, the BACnet Device object, OPC UA GetEndpoints,
  PROFINET I&M0, …).
- **Deterministic, graded confidence** — a shared [confidence
  scale](FINGERPRINTS.md#confidence); a match is backed by evidence a caller
  can inspect.
- **Zero runtime dependencies** — standard library only (the CLI adds
  cobra). The sibling `go-<protocol>` libraries and `*-interop` suites are
  used to validate the fingerprinters, never imported at runtime.
- **OT-safe scanning** — a conservative mode that sends passive probes only,
  the likely protocols of a port first, and paces probes to stay under IDS
  thresholds.

## Installation

```bash
go get github.com/otfabric/go-otfp          # library
go install github.com/otfabric/go-otfp/cmd/otprobe@latest  # CLI
```

## CLI — `otprobe`

```bash
otprobe detect 10.0.0.5:502                 # scan one TCP port
otprobe detect 10.0.0.5:502 --identify      # also read device identity
otprobe detect udp://10.0.0.5:47808         # BACnet / PROFINET (UDP)
otprobe detect tls://10.0.0.5:802           # Modbus Security (TLS)
otprobe detect 10.0.0.5:4840 --format json  # machine-readable output
otprobe detect 10.0.0.5:502 --safe          # OT-safe pacing, passive only
otprobe list                                # the protocols and their probes
```

Exit codes: `0` detected (high confidence), `1` no match, `2` connection
error, `3` bad arguments, `4` matched below the high-confidence threshold.
See `otprobe detect --help` for every flag.

## Library

```go
package main

import (
	"context"
	"fmt"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
)

func main() {
	engine := otfp.NewEngine(core.EngineConfig{Mode: core.ModeIdentify})
	report, err := engine.Scan(context.Background(), core.Target{
		Host: "10.0.0.5", Port: 502,
	})
	if err != nil {
		panic(err)
	}
	if report.Best.Matched {
		fmt.Printf("%s (%.2f) %s\n", report.Best.Protocol, report.Best.Confidence, report.Best.Identity)
	}
}
```

Detect a single protocol with `engine.Detect(ctx, target, core.ProtocolModbus)`,
or build a custom registry from `core.NewRegistry()` and your own
`core.Fingerprinter` implementations. The full API is in [API.md](API.md).

## Project layout

```
go-otfp/
├── otfp.go            DefaultRegistry / DefaultEngine convenience
├── core/              Protocol, Target, Result/Identity/Confidence,
│                      Fingerprinter, Registry, Engine, typed errors
├── internal/
│   ├── wire/          framed TCP/TLS/UDP sessions with error classification
│   ├── iso/           TPKT + COTP (shared by MMS and S7)
│   ├── mbap/          Modbus MBAP framing (shared by Modbus and SunSpec)
│   ├── httpx/         minimal HTTP/1.1 over a session (web protocols)
│   ├── fpx/           evidence/identity/fingerprint scoring helper
│   ├── testsrv/       scripted loopback servers for tests
│   └── cmd/gencip/    generator for the EtherNet/IP CIP catalogue
├── protocols/         one package per protocol (see the table above)
├── cmd/otprobe/       the CLI
├── interop/           Docker-gated tests against the pinned reference servers
└── docs …             API, ARCHITECTURE, FINGERPRINTS, ERRORS, …
```

## Building and testing

```bash
make build           # build ./bin/otprobe
make check           # fmt, lint, vet, govulncheck, race tests, coverage
make test-race       # race tests only
make fuzz            # fuzz every parser (FUZZTIME=…)
make interop         # detect the pinned reference servers (needs Docker)
```

## Documentation

- [API.md](API.md) — every exported type and function
- [ARCHITECTURE.md](ARCHITECTURE.md) — engine, sessions and the scoring path
- [FINGERPRINTS.md](FINGERPRINTS.md) — per-protocol probes, bytes and confidence
- [ERRORS.md](ERRORS.md) — the error taxonomy
- [OBSERVABILITY.md](OBSERVABILITY.md) — logging, the Observer and tracing
- [INTEROPERABILITY.md](INTEROPERABILITY.md) — the reference servers and how they are pinned
- [SECURITY.md](SECURITY.md) — safe use in OT networks and reporting issues
- [CONTRIBUTING.md](CONTRIBUTING.md) · [RELEASE.md](RELEASE.md)

## License

MIT — see [LICENSE](LICENSE).
