# otfp — OT Protocol Fingerprinting Library

[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/otfabric/go-otfp.svg)](https://pkg.go.dev/github.com/otfabric/go-otfp)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/otfabric/go-otfp/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/go-otfp/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/otfabric/go-otfp/graph/badge.svg)](https://codecov.io/gh/otfabric/go-otfp)
[![Release](https://img.shields.io/github/v/release/otfabric/go-otfp?label=release)](https://github.com/otfabric/go-otfp/releases)


A pure Go library for OT (Operational Technology) protocol fingerprinting at
the **connection level only**. Detects industrial protocols based on transport
framing and handshake behavior — without invoking application-layer logic.

**Stability:** this module is still `v0.0.x`. Public APIs may change between
minor tags; pin a specific version and review release notes before upgrading.

## Table of contents

- [Supported Protocols](#supported-protocols)
  - [Protocol Overview](#protocol-overview)
  - [TCP Detectability Notes](#tcp-detectability-notes)
  - [Energy & Utility Protocol Coverage](#energy--utility-protocol-coverage)
- [Key Principles](#key-principles)
- [Project structure](#project-structure)
- [Installation](#installation)
- [CLI Usage (`otprobe`)](#cli-usage-otprobe)
- [Library Usage](#library-usage)
- [Architecture](#architecture)
- [Detection Details](#detection-details)
- [Security Considerations](#security-considerations)
- [Building & Testing](#building--testing)
- [Documentation](#documentation)
- [License](#license)

---

## Project structure

```
go-otfp/
├── otfp.go            Convenience: DefaultRegistry()
├── core/              Engine, registry, Result/Confidence, typed errors
├── transport/         Shared TCP dial / send-receive helpers
├── protocols/         Per-protocol fingerprinters (+ shared iso/ for TPKT/COTP)
├── cmd/otprobe/       CLI (detect / list / version)
├── wireshark/         Capture / dissection notes per protocol
├── API.md             Public API reference
├── ERRORS.md          Error taxonomy (match vs typed failures)
├── RELEASE.md         Release history
└── README.md
```

Detection orchestration and file-level layout are detailed under
[Architecture](#architecture). Error taxonomy: [ERRORS.md](ERRORS.md).

---

## Supported Protocols

| Protocol | Detection Method | Phase |
|---|---|---|
| **Modbus TCP** | MBAP header validation, Transaction ID echo, FC validation | Single exchange |
| **IEC 61850 MMS** | TPKT/COTP Connection Request → Confirm | Single exchange |
| **Siemens S7comm** | TPKT/COTP CR→CC + S7 Setup Communication → ACK | Two-phase |
| **OPC UA** | HEL/ACK binary handshake | Single exchange |
| **BACnet/IP** | BVLL Who-Is broadcast probe | Single exchange |
| **CAN (TCP Gateway)** | SLCAN ASCII command probe | Single exchange |
| **PROFINET** | DCE/RPC Bind with PNIO CM UUID | Single exchange |
| **DNP3** | Link-layer start bytes + CRC validation | Single exchange |
| **IEC 60870-5-104** | APCI STARTDT_ACT/CON handshake | Single exchange |
| **EtherNet/IP** | Encapsulation RegisterSession handshake | Single exchange |

### Protocol Overview

| Protocol | Description | Typical Use Case | Default Port |
|---|---|---|---|
| **Modbus TCP** | Simple request/response industrial protocol for reading and writing registers over TCP. | PLC communication, RTUs, industrial sensors, legacy automation systems. | 502 |
| **IEC 61850 MMS** | Manufacturing Message Specification over ISO-on-TCP for substation automation. | Electrical substations, protection relays, SCADA in power grids. | 102 |
| **Siemens S7comm** | Siemens proprietary protocol over ISO-on-TCP for PLC programming and runtime communication. | Siemens PLCs (S7-300/400/1200/1500) in factory automation. | 102 |
| **OPC UA (Binary)** | Platform-independent, secure, service-oriented industrial communication protocol. | SCADA systems, Industry 4.0 integration, MES/ERP connectivity. | 4840 |
| **BACnet/IP** | Building Automation and Control protocol using BVLL over IP networks. | HVAC, lighting control, building management systems (BMS). | 47808 |
| **CAN (TCP Gateway)** | CAN bus access exposed via TCP through gateways (e.g., SLCAN ASCII). | Embedded systems, automotive testing, industrial field devices via IP bridge. | Varies (commonly 3000, 2000, vendor-specific) |
| **PROFINET** | Industrial Ethernet standard for real-time automation, successor to PROFIBUS. | Factory automation, distributed I/O, motion control. | 34964 (RPC), also 34962–34964 |
| **DNP3 (TCP)** | Distributed Network Protocol for reliable telemetry and control in utilities. | Electric power transmission/distribution, water utilities, remote RTUs. | 20000 |
| **IEC 60870-5-104** | European SCADA protocol over TCP for telecontrol systems. | Substations, grid control centers, energy distribution networks. | 2404 |
| **EtherNet/IP (CIP)** | Common Industrial Protocol over TCP/IP using encapsulation layer. | Rockwell / Allen-Bradley PLCs, industrial drives, factory automation. | 44818 |

### TCP Detectability Notes

All protocols above are detectable over raw TCP connections. Some notes on
real-world deployments:

- **PROFIBUS** uses RS-485 serial and is not directly detectable over TCP.
  PROFINET is its TCP/IP successor.
- **CAN** detection targets TCP-to-CAN gateways that expose an SLCAN ASCII
  interface over a TCP socket.

### Energy & Utility Protocol Coverage

- **DNP3** and **IEC 60870-5-104** are the dominant SCADA protocols in power
  grid infrastructure. DNP3 is prevalent in North America; IEC 104 dominates
  European substations.
- **EtherNet/IP** (CIP over TCP) is the primary protocol in Rockwell /
  Allen-Bradley factory automation environments.

---

## Key Principles

- **TCP port agnostic** — does not assume Modbus=502, ISO=102
- **Connection-level only** — no register reads, no device-info queries, no
  deep parsing
- **Minimal payloads** — standards-compliant, safe for ICS environments
- **Deterministic detection** — confidence scoring based on protocol framing
  validation
- **Priority-based ordering** — protocols tested in optimal priority order
  with early stop
- **Typed confidence scoring** — `Confidence` type with `Valid()` and
  `IsHigh()` methods
- **Structured fingerprints** — `Fingerprint` type with ID, Signature, and
  Metadata
- **Structured error handling** — typed errors (`TimeoutError`,
  `ConnectionError`, `InvalidResponseError`, `DetectError`)
- **Observability** — `Observer` interface for scan progress / audit callbacks
  (`OnStart` / `OnResult`), not request-latency metrics
- **Rate limiting** — configurable `MinInterval` between probes for IDS-safe
  scanning
- **Audit trail** — every `Result` carries a unique `DetectionID` and
  `Timestamp`
- **Signal safety** — graceful shutdown on SIGINT/SIGTERM via context
  cancellation

---

## Installation

### Library

```bash
go get github.com/otfabric/go-otfp
```

### CLI Tool

```bash
go install github.com/otfabric/go-otfp/cmd/otprobe@latest
```

---

## CLI Usage (`otprobe`)

`otprobe` uses a **subcommand architecture** powered by [cobra](https://github.com/spf13/cobra):

```
otprobe <command> [flags]
```

### Commands

| Command   | Description |
|-----------|-------------|
| `detect`  | Detect OT protocols on a target endpoint |
| `list`    | List supported protocols with priorities |
| `version` | Print version information (Go version, platform, build metadata) |

### `otprobe detect`

Full detection (all protocols):

```bash
otprobe detect --ip 192.168.1.10 --port 102
```

Output:

```
Target: 192.168.1.10:102
Detected: Siemens S7comm
Confidence: 0.95 (high)
```

Protocol-specific check:

```bash
otprobe detect --ip 192.168.1.10 --port 502 --check modbus
```

JSON output with structured error and confidence level:

```bash
otprobe detect --ip 192.168.1.10 --port 502 --output json
```

```json
{
  "target": "192.168.1.10:502",
  "protocol": "Modbus TCP",
  "matched": true,
  "confidence": 0.95,
  "confidence_level": "high",
  "details": "MBAP header valid, TxID echoed",
  "fingerprint": {
    "id": "modbus.fc43",
    "signature": "MBAP header valid, TxID echoed"
  },
  "detection_id": "a1b2c3d4e5f67890",
  "timestamp": "2025-01-15T10:30:00.123456789Z"
}
```

### `otprobe list`

```bash
otprobe list
```

```
  mms          IEC 61850 MMS (priority 10)
  s7           Siemens S7comm (priority 20)
  enip         EtherNet/IP (priority 30)
  iec104       IEC 60870-5-104 (priority 40)
  dnp3         DNP3 (TCP) (priority 50)
  modbus       Modbus TCP (priority 60)
  opcua        OPC UA (priority 70)
  bacnet       BACnet/IP (priority 80)
  can          CAN (TCP Gateway) (priority 90)
  profinet     PROFINET (Ethernet) (priority 100)
```

### `otprobe version`

```bash
otprobe version
```

```
otprobe version 0.1.0
  branch:     main
  revision:   abc1234
  build user: ci
  build date: 20250115-10:30:00
  go version: go1.23.0
  platform:   linux/amd64
```

### Dry-Run Mode

For change-controlled OT environments — shows what **would** be tested
without sending any network traffic:

```bash
otprobe detect --dry-run --ip 10.0.0.1 --port 502
```

```
Dry-run: no network traffic will be sent

Target:          10.0.0.1:502
Timeout:         5s
Global Timeout:  0s
Parallel:        false
Safe mode:       false
Max concurrency: 0

Protocol detection order:
   1. mms          IEC 61850 MMS (priority 10)
   2. s7           Siemens S7comm (priority 20)
  ...
```

### OT-Safe Mode

For production ICS/SCADA environments where minimising network impact is
critical:

```bash
otprobe detect --ip 192.168.1.10 --port 502 --safe
```

Safe mode enforces:
- Sequential detection (`--parallel=false`)
- Max concurrency 1
- 200ms minimum interval between probes

### Detect Flags

| Flag | Description | Default |
|---|---|---|
| `--ip` | Target IP address (required) | — |
| `--port` | Target TCP port (required) | — |
| `--check` | Check specific protocol: `modbus`, `mms`, `s7`, `opcua`, `bacnet`, `can`, `profinet`, `dnp3`, `iec104`, `enip` | (all) |
| `--timeout` | Per-protocol connection timeout | `5s` |
| `--global-timeout` | Overall timeout for the entire run (0 = unlimited) | `0` |
| `--verbose` | Show detailed detection results | `false` |
| `--debug` | Enable debug logging (per-protocol timings, connection errors) | `false` |
| `--quiet` | Suppress non-error log output | `false` |
| `--parallel` | Run protocol checks in parallel | `false` |
| `--safe` | OT-safe mode: sequential, min-interval=200ms, max-concurrency=1 | `false` |
| `--max-concurrency` | Maximum parallel goroutines (0 = unbounded) | `0` |
| `--output` | Output format: `text` or `json` | `text` |
| `--dry-run` | Show detection plan without sending network traffic | `false` |

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Protocol detected (high confidence ≥ 0.9) |
| 1 | Unknown protocol (no match) |
| 2 | Connection error (transport-level failure: timeout, refused, unreachable) |
| 3 | Invalid parameters |
| 4 | Partial detection (matched but confidence < 0.9) |

Exit codes are a **stable numeric API** — scripts can rely on them:

```bash
otprobe detect --ip 10.0.0.1 --port 502 --output json
case $? in
  0) echo "Detected with high confidence" ;;
  1) echo "No protocol detected" ;;
  2) echo "Transport-level failure" ;;
  4) echo "Low-confidence detection — manual review" ;;
esac
```

> **Note:** Exit code 2 always means "transport-level failure" — this includes
> DNS resolution failures, timeouts, and connection refused errors.

### Ambiguity Warning

When multiple protocols match with medium confidence (< 0.9), `otprobe`
prints a warning and returns exit code 4:

```
Warning: 2 protocols matched with medium confidence — manual review recommended
```

---

## Library Usage

For complete API documentation, see **[API.md](API.md)**.

### Basic Detection

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/otfabric/go-otfp/core"
    "github.com/otfabric/go-otfp/protocols/modbus"
    "github.com/otfabric/go-otfp/protocols/mms"
    "github.com/otfabric/go-otfp/protocols/s7"
)

func main() {
    registry := core.NewRegistry()
    _ = registry.Register(mms.New())
    _ = registry.Register(s7.New())
    _ = registry.Register(modbus.New())

    engine := core.NewEngine(registry, core.DefaultEngineConfig())

    target := core.Target{
        IP:      "192.168.1.10",
        Port:    502,
        Timeout: 5 * time.Second,
    }

    result := engine.Detect(context.Background(), target)
    fmt.Printf("Protocol: %s\n", result.Protocol)
    fmt.Printf("Matched:  %v\n", result.Matched)
    fmt.Printf("Confidence: %.2f\n", result.Confidence)
    fmt.Printf("DetectionID: %s\n", result.DetectionID)
}
```

### Convenience: DefaultRegistry

```go
import "github.com/otfabric/go-otfp"

registry := otfp.DefaultRegistry() // all 10 protocols, canonical order
engine := core.NewEngine(registry, core.DefaultEngineConfig())
```

### Single Protocol Check

```go
result, err := engine.DetectProtocol(ctx, target, core.ProtocolModbus)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Modbus: %v (confidence %.2f)\n", result.Matched, result.Confidence)
```

### ScanReport with Observer

```go
type logger struct{}

func (l *logger) OnStart(p core.Protocol, t core.Target) {
    fmt.Printf("  probing %s on %s\n", p, t.Addr())
}
func (l *logger) OnResult(r core.Result) {
    fmt.Printf("  result: %s matched=%v confidence=%.2f\n",
        r.Protocol, r.Matched, r.Confidence)
}

func scan() {
    reg := otfp.DefaultRegistry()

    config := core.DefaultEngineConfig()
    config.Observer = &logger{}
    config.MinInterval = 100 * time.Millisecond

    engine := core.NewEngine(reg, config)
    report := engine.Scan(context.Background(),
        core.Target{IP: "10.0.0.1", Port: 502})

    fmt.Printf("Scan took %v, best: %s (%.2f)\n",
        report.Duration, report.BestMatch.Protocol,
        report.BestMatch.Confidence)
}
```

### OT-Safe Engine

```go
config := core.SafeEngineConfig()
config.MinInterval = 200 * time.Millisecond
engine := core.NewEngine(registry, config)
```

### Target Validation

```go
target := core.Target{IP: "192.168.1.1", Port: 502, Timeout: 5 * time.Second}
if err := target.Validate(); err != nil {
    log.Fatalf("bad target: %v", err)
}
```

### Custom Fingerprinter

```go
// Custom protocols must use a Protocol constant registered with the library.
// For illustration, this example reuses an existing constant.
type MyProtocolFingerprinter struct{}

func (f *MyProtocolFingerprinter) Name() core.Protocol { return core.ProtocolModbus }
func (f *MyProtocolFingerprinter) Priority() int       { return 200 }

func (f *MyProtocolFingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
    // Your detection logic here...
    result := core.Match(core.ProtocolModbus, 0.9, "valid response")
    return result.WithFingerprint(&core.Fingerprint{
        ID:        "custom.probe",
        Signature: "valid response",
    }), nil
}

registry.Register(&MyProtocolFingerprinter{})
```

---

## Architecture

```
go-otfp/
├── otfp.go                    # Convenience: DefaultRegistry()
├── core/                      # Core types and engine
│   ├── engine.go              # Detection orchestration (parallel/sequential, observer, rate-limit)
│   ├── classify.go            # ClassifyDial / ClassifyIO → typed errors
│   ├── errors.go              # Typed errors (DetectError, TimeoutError, ConnectionError, …)
│   ├── fingerprinter.go       # Fingerprinter interface (Name, Priority, Detect)
│   ├── protocol.go            # Protocol uint8 enum with stable constants
│   ├── registry.go            # Thread-safe protocol registry (priority-sorted)
│   ├── result.go              # Result, Confidence, Fingerprint, DetectionID
│   └── target.go              # Target definition with Validate()
├── transport/                 # Shared TCP transport utilities
│   └── tcp.go                 # TCP connection helpers
├── protocols/                 # Protocol implementations
│   ├── iso/                   # Shared ISO-on-TCP (RFC 1006) utilities
│   ├── modbus/ mms/ s7/ opcua/ bacnet/ can/
│   ├── profinet/ dnp3/ iec104/ enip/
├── cmd/otprobe/               # CLI (cobra: detect / list / version; ldflags versioning)
├── wireshark/                 # Per-protocol capture notes
├── API.md                     # Library API reference
├── ERRORS.md                  # Error taxonomy
├── RELEASE.md                 # Release history
└── README.md
```

---

## Detection Details

### Modbus TCP

Sends a minimal Modbus TCP frame using **FC43 (Read Device Identification)** —
a safe, read-only diagnostic function:

1. Constructs MBAP header with known Transaction ID (0x1337)
2. Validates response: Protocol ID=0, Transaction ID echo, length consistency,
   function code
3. Accepts both normal and exception responses as valid Modbus

**Confidence factors:**

- Protocol ID = 0x0000 (+0.25)
- Transaction ID echoed (+0.25)
- Length field consistent (+0.20)
- Valid function code / exception (+0.20)
- Unit ID echoed (+0.10)

### IEC 61850 MMS (ISO-on-TCP)

Sends a **TPKT/COTP Connection Request** with generic TSAP parameters:

1. Validates TPKT header (version 0x03, reserved 0x00)
2. Validates COTP Connection Confirm (CC) PDU type
3. Checks TPDU class and length consistency

**Confidence factors:**

- Valid TPKT header (+0.30)
- COTP CC received (+0.35)
- Length consistent (+0.15)
- CC structure valid (+0.15)
- Class 0 confirmed (+0.05)

### Siemens S7comm

Two-phase detection that distinguishes S7 from pure MMS:

**Phase 1:** TPKT/COTP CR → CC (same as MMS, with S7-specific TSAP: rack 0 /
slot 2)

**Phase 2:** S7 Setup Communication → S7 ACK-Data

1. Validates S7 protocol magic (0x32)
2. Checks message type (Ack-Data = 0x03)
3. Validates error class/code
4. Confirms Setup Communication function code (0xF0)

**Confidence factors:**

- COTP CC confirmed (+0.35)
- S7 Protocol ID 0x32 (+0.25)
- Ack-Data response (+0.20)
- No error (+0.10)
- Setup Comm function confirmed (+0.10)

### OPC UA (Binary)

Sends an **OPC UA HEL (Hello)** message and validates the ACK response:

1. Constructs a minimal HEL message with endpoint URL
   `opc.tcp://<ip>:<port>`
2. Validates ACK message type signature ("ACK")
3. Checks message size, protocol version, and buffer size fields

**Confidence factors:**

- ACK message type received (+0.40)
- Message size plausible (+0.20)
- Protocol version valid (+0.20)
- Buffer sizes reasonable (+0.20)

### BACnet/IP (BVLL)

Sends a **BVLL Original-Unicast-NPDU** containing a **Who-Is** service
request:

1. Constructs BVLL header (type 0x81) with Original-Unicast function (0x0A)
2. Includes minimal NPDU with Who-Is APDU
3. Validates response BVLL type byte and function code

**Confidence factors:**

- BVLL type byte 0x81 (+0.40)
- Valid BVLL function code (+0.30)
- Length field consistent (+0.20)
- NPDU version present (+0.10)

### CAN (TCP Gateway)

Probes for **SLCAN** (Serial Line CAN) ASCII protocol over TCP:

1. Sends `V\r` (version query) and checks for ASCII response
2. Sends `N\r` (serial number query) as a second probe
3. Validates response contains printable ASCII terminated by CR

**Confidence factors:**

- ASCII printable content (+0.40)
- CR-terminated response (+0.20)
- SLCAN command pattern match (+0.40)

### PROFINET (DCE/RPC)

Sends a **DCE/RPC Bind** request with the PNIO Connection Manager UUID:

1. Constructs DCE/RPC Bind PDU (type 0x0B) with PNIO CM interface UUID
2. Validates Bind-Ack response (type 0x0C)
3. Checks for accepted PNIO transfer syntax

**Confidence factors:**

- Bind-Ack received (+0.40)
- Fragment length valid (+0.10)
- PNIO transfer syntax accepted (+0.50)

### DNP3 (TCP)

Sends a minimal **DNP3 Link Status Request** frame with valid CRC:

1. Constructs link-layer frame with start bytes `0x05 0x64`
2. Uses Function Code 0x09 (Link Status Request) with computed CRC-16
3. Validates response start bytes, length, CRC, and control field

**Confidence factors:**

- Start bytes 0x05 0x64 (+0.40)
- Valid length field (+0.20)
- Valid CRC-16 (+0.20)
- Valid response control code (+0.20)

### IEC 60870-5-104

Sends a **STARTDT_ACT** U-format APCI frame and validates the confirmation:

1. Sends 6-byte APCI frame: `68 04 07 00 00 00`
2. Validates start byte `0x68` and APCI length
3. Checks for STARTDT_CON (`0x0B`) or other valid U/S-format response

**Confidence factors:**

- Start byte 0x68 (+0.30)
- Length field valid (+0.20)
- Valid U/S-format control field (+0.30)
- STARTDT_CON received (+0.20)

### EtherNet/IP (CIP over TCP)

Sends a **RegisterSession** encapsulation command and validates the response:

1. Constructs 28-byte RegisterSession request (command 0x0065, protocol
   version 1)
2. Validates response command code, status, and session handle
3. Non-zero session handle confirms active EtherNet/IP endpoint

**Confidence factors:**

- Command echo 0x0065 (+0.30)
- Status = Success (+0.20)
- Session ID non-zero (+0.30)
- Length field valid (+0.20)

---

## Security Considerations

This library is designed for safe use in ICS/SCADA environments:

- **No aggressive scanning** — one minimal request per protocol check; the S7 probe sends two (COTP connect, then S7 setup) and the CAN probe two (version, then serial)
- **No malformed payloads** — all probes are standards-compliant
- **No exploit patterns** — uses safe, read-only diagnostic functions
- **No flooding** — one connection per check, graceful close
- **Minimal footprint** — probes are the smallest valid frames possible
- **Context-aware** — supports cancellation and configurable timeouts
- **OT-safe mode** — sequential scanning with bounded concurrency and 200ms
  inter-probe delay
- **Rate limiting** — `MinInterval` between probes prevents IDS alerts
- **Signal handling** — SIGINT/SIGTERM trigger graceful context cancellation
- **Dry-run** — preview the detection plan without sending any traffic

> **Warning:** Even minimal protocol probes may trigger alerts in some IDS/IPS
> systems configured for OT environments. Always obtain proper authorization
> before scanning industrial networks.

---

## Building & Testing

```bash
# Build the CLI binary
make build

# Install to GOPATH/bin
make install

# Run lint + vet + tests
make check

# Run all tests
go test ./... -v

# Run with race detector
go test ./... -race

# Run specific protocol tests
go test ./protocols/modbus/ -v
go test ./protocols/mms/ -v
go test ./protocols/s7/ -v

# Run fuzz tests (Go 1.18+)
go test ./protocols/modbus/ -fuzz=FuzzValidateResponse -fuzztime=30s
```

---

## Documentation

- [API.md](API.md) — Public API reference: engine, results, protocols, CLI JSON shapes.
- [ERRORS.md](ERRORS.md) — Match vs typed errors; `ClassifyDial` / `ClassifyIO`; `errors.As` patterns.
- [RELEASE.md](RELEASE.md) — Release history.

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).
