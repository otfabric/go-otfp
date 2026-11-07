# go-otfp — OT protocol fingerprinting

[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
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
| **CANopen** (CiA 309-3 gateway) | TCP | 60000 (CANopenNode) | `info version` with an echoed sequence number | gateway version record; node vendor-ID, product code, revision, serial, device type, name, software version (SDO, read-only) |
| **KNXnet/IP** | UDP + TCP | 3671 | DESCRIPTION_REQUEST (route-back HPAI) | friendly name, medium, individual address, serial, MAC, service families, Secure/Tunnelling v2 |
| **MQTT** (3.1.1 / 5) | TCP (TLS) | 1883/8883 | CONNECT/CONNACK, PINGREQ, DISCONNECT | protocol version, CONNACK properties, `$SYS/broker/version` |
| **Sparkplug B** | TCP (TLS) | 1883/8883 | QoS 0 SUBSCRIBE to STATE and spBv1.0 topics, bounded window (refines MQTT) | host applications, groups, edge nodes, devices, NBIRTH bdSeq/metrics |

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

### Library

```bash
go get github.com/otfabric/go-otfp
```

Go 1.26 or later; standard library only. The CLI is a nested module, so the
library does not pull in its dependencies (cobra).

### CLI — `otprobe`

The easiest way to install otprobe is to download a pre-built binary from the [GitHub Releases page](https://github.com/otfabric/go-otfp/releases). No Go toolchain is required.

| Platform | CPU | Download |
|---|---|---|
| Linux | x86-64 | `otprobe-<version>-linux-amd64.tar.gz` |
| Linux | 64-bit ARM (Raspberry Pi 4/5 with a 64-bit OS, AWS Graviton) | `otprobe-<version>-linux-arm64.tar.gz` |
| Linux | 32-bit ARM (Raspberry Pi with a 32-bit OS) | `otprobe-<version>-linux-armv7.tar.gz` |
| macOS | Apple Silicon (M1 and later) | `otprobe-<version>-darwin-arm64.tar.gz` |
| macOS | Intel | `otprobe-<version>-darwin-amd64.tar.gz` |
| Windows | x86-64 | `otprobe-<version>-windows-amd64.zip` |
| Windows | ARM64 | `otprobe-<version>-windows-arm64.zip` |

Each release also contains `otprobe-<version>-checksums.txt` (SHA-256) so you can verify your download. The commands below fetch the **latest** release, verify its checksum and install it. Afterwards, check that it works:

```console
otprobe version
```

#### Linux

```bash
# 1. Find the latest version and your CPU architecture
VERSION=$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/otfabric/go-otfp/releases/latest | sed 's|.*/v||')
case "$(uname -m)" in
  x86_64)         ARCH=amd64 ;;
  aarch64|arm64)  ARCH=arm64 ;;
  armv7l)         ARCH=armv7 ;;
  *) echo "Unsupported architecture: $(uname -m)" ;;
esac

# 2. Download the archive and the checksum file
FILE="otprobe-${VERSION}-linux-${ARCH}.tar.gz"
BASE="https://github.com/otfabric/go-otfp/releases/download/v${VERSION}"
curl -fsSLO "${BASE}/${FILE}"
curl -fsSLO "${BASE}/otprobe-${VERSION}-checksums.txt"

# 3. Verify the download (should print "OK")
grep "${FILE}" "otprobe-${VERSION}-checksums.txt" | sha256sum -c -

# 4. Extract and install (the binary in the archive carries the version and platform in its name)
mkdir -p otprobe-dl && tar -xzf "${FILE}" -C otprobe-dl
sudo install -m 0755 "$(find otprobe-dl -type f -name 'otprobe*' | head -n1)" /usr/local/bin/otprobe
```

No `sudo`? Install into your home directory instead (and make sure `~/.local/bin` is in your `PATH`):

```bash
mkdir -p ~/.local/bin
install -m 0755 "$(find otprobe-dl -type f -name 'otprobe*' | head -n1)" ~/.local/bin/otprobe
```

#### macOS

```bash
# 1. Find the latest version and your CPU architecture (arm64 = Apple Silicon, x86_64 = Intel)
VERSION=$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/otfabric/go-otfp/releases/latest | sed 's|.*/v||')
case "$(uname -m)" in
  arm64)   ARCH=arm64 ;;
  x86_64)  ARCH=amd64 ;;
esac

# 2. Download the archive and the checksum file
FILE="otprobe-${VERSION}-darwin-${ARCH}.tar.gz"
BASE="https://github.com/otfabric/go-otfp/releases/download/v${VERSION}"
curl -fsSLO "${BASE}/${FILE}"
curl -fsSLO "${BASE}/otprobe-${VERSION}-checksums.txt"

# 3. Verify the download (should print "OK")
grep "${FILE}" "otprobe-${VERSION}-checksums.txt" | shasum -a 256 -c -

# 4. Extract and install (the binary in the archive carries the version and platform in its name)
mkdir -p otprobe-dl && tar -xzf "${FILE}" -C otprobe-dl
sudo install -m 0755 "$(find otprobe-dl -type f -name 'otprobe*' | head -n1)" /usr/local/bin/otprobe
```

If you downloaded the archive with a web browser instead of `curl` and macOS refuses to run the binary ("cannot be verified"), remove the quarantine flag: `xattr -d com.apple.quarantine /usr/local/bin/otprobe`.

#### Windows (PowerShell)

```powershell
# 1. Find the latest version and your CPU architecture
$version = (Invoke-RestMethod https://api.github.com/repos/otfabric/go-otfp/releases/latest).tag_name.TrimStart('v')
$arch    = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }

# 2. Download the archive and the checksum file
$file = "otprobe-$version-windows-$arch.zip"
$base = "https://github.com/otfabric/go-otfp/releases/download/v$version"
Invoke-WebRequest "$base/$file" -OutFile "$env:TEMP\$file"
Invoke-WebRequest "$base/otprobe-$version-checksums.txt" -OutFile "$env:TEMP\otprobe-checksums.txt"

# 3. Verify the download (throws an error on mismatch)
$expected = ((Select-String -Path "$env:TEMP\otprobe-checksums.txt" -Pattern $file).Line -split '\s+')[0]
$actual   = (Get-FileHash "$env:TEMP\$file" -Algorithm SHA256).Hash
if ($expected -ne $actual) { throw "Checksum mismatch for $file" }

# 4. Extract to a per-user folder and name the program otprobe.exe
#    (the .exe in the archive carries the version and platform in its name)
$dir = "$env:LOCALAPPDATA\Programs\otprobe"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Expand-Archive "$env:TEMP\$file" -DestinationPath "$env:TEMP\otprobe-dl" -Force
$exe = Get-ChildItem "$env:TEMP\otprobe-dl" -Recurse -Filter 'otprobe*.exe' | Select-Object -First 1
Copy-Item $exe.FullName "$dir\otprobe.exe" -Force

# 5. Add otprobe to your user PATH (then open a new terminal)
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$dir*") {
  [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
}
```

If Windows SmartScreen warns about an unrecognised app, choose **More info → Run anyway**.

#### Manual download

1. Open the [latest release](https://github.com/otfabric/go-otfp/releases/latest).
2. Download the archive for your platform from the table above.
3. Extract it, rename the binary to `otprobe` (`otprobe.exe` on Windows) and move it to a folder on your `PATH`.

#### Update

Run the same commands again. They always fetch the latest release and overwrite the previous binary.

#### Shell completion

`otprobe completion bash|zsh|fish|powershell` prints a completion script for commands, flags, protocol slugs and ports, for example `otprobe completion zsh > "${fpath[1]}/_otprobe"`. See [cmd/otprobe/docs/cli.md](cmd/otprobe/docs/cli.md#shell-completion).

#### Build from source

Requires Go 1.26 or later:

```console
git clone https://github.com/otfabric/go-otfp.git
cd go-otfp
make build
```

`make build` writes the binary to **`bin/otprobe`** with its version, commit and build date stamped in. With a Go toolchain you can also install straight from the module:

```console
go install github.com/otfabric/go-otfp/cmd/otprobe@latest
```

This builds the latest commit on `main` (the CLI module has no version tags of its own), and `otprobe version` then reports `dev`; prefer a release binary for a known version.

## CLI — `otprobe`

```console
$ otprobe detect 127.0.0.1:44818 --identify
Target:   tcp://127.0.0.1:44818
Detected: EtherNet/IP, confidence 1.00

  EtherNet/IP  1.00  EtherNet/IP device
    - ListIdentity: Rockwell Automation/Allen-Bradley, product "OpENer PC"
    - session registered (handle 0x00000001)
    vendor       Rockwell Automation/Allen-Bradley
    vendor id    1
    product      OpENer PC
    version      2.3
    serial       0x075BCD15
    deviceType   Communications Adapter
    productCode  65001
    fingerprint  enip.listidentity:vendor=1;devtype=0x0c;product=65001;rev=2.3;session=ok

  1 probe in 2ms
```

(Real output from the OpENer reference adapter of `ethernetip-interop`.)

```bash
otprobe detect 10.0.0.5:502 --identify      # one TCP port, with device identity
otprobe detect udp://10.0.0.5:47808         # BACnet / PROFINET / EtherNet/IP over UDP
otprobe detect tls://10.0.0.5:802           # over TLS (Modbus Security, wss://, https://)
otprobe detect 10.0.0.5 --safe              # sweep the well-known ports, OT-safe pacing
otprobe detect 10.0.0.5:4840 -o table       # one row per probe; -o json for machines
otprobe list                                # the protocols and their probes
otprobe completion zsh > "${fpath[1]}/_otprobe"   # completion of commands, flags and values
```

Text is the default output; `--format table` and `--format json` (versioned
schema) are available on every command. Exit codes are stable for scripts:
`0` detected, `1` no match, `2` usage, `3` invalid input, `4` unreachable,
`5` timeout, `7` matched below high confidence, `10` interrupted. The full
reference with real output for every protocol is [cmd/otprobe/docs/cli.md](cmd/otprobe/docs/cli.md);
see also [cmd/otprobe/docs/exitcodes.md](cmd/otprobe/docs/exitcodes.md) and
[cmd/otprobe/docs/json-output.md](cmd/otprobe/docs/json-output.md).

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

### Examples

Runnable programs in [examples/](examples/); each starts a demo device on
loopback when run without arguments, so it works offline, and probes a real
endpoint when given one:

| Example | Shows |
|---|---|
| [quickstart](examples/quickstart/main.go) | scan one endpoint with the default engine |
| [identify](examples/identify/main.go) | detect one protocol and read the device identity |
| [sweep](examples/sweep/main.go) | several ports with the OT-safe engine |
| [custom](examples/custom/main.go) | a fingerprinter of your own, next to the built-in ones |
| [observe](examples/observe/main.go) | progress Observer, slog logging, raw-byte tracing |

```bash
go run ./examples/identify
go run ./examples/identify 10.0.0.5:44818 enip
```

The package documentation on pkg.go.dev carries `Example` functions as well.

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
│   ├── tlsx/          the one non-verifying TLS client configuration
│   ├── testsrv/       scripted loopback servers for tests
│   └── cmd/gencip/    generator for the EtherNet/IP CIP catalogue
├── protocols/         one package per protocol (see the table above)
├── cmd/otprobe/       the CLI (nested module)
├── interop/           Docker-gated tests against the pinned reference servers
└── docs …             API, ARCHITECTURE, FINGERPRINTS, ERRORS, …
```

## Building and testing

```bash
make build           # build ./bin/otprobe
make check           # fmt, lint, vet, govulncheck, race tests, coverage, examples
make test-race       # race tests only
make stress          # every test 10x with -race in shuffled order (STRESS=…)
make fuzz            # fuzz every parser and every fingerprinter end to end (FUZZTIME=…)
make interop         # detect the pinned reference servers (needs Docker)
```

Beyond unit tests, the suite hunts for bugs in four ways:

- **End-to-end fuzzing** (`FuzzDetect` in every protocol package): a loopback
  server answers the fingerprinter's probes with fuzzed bytes, seeded with
  replies captured from the reference servers, and every result is checked
  against the Fingerprinter contract — bounded time, no panic, an error only
  for transport failures, `Matched` consistent with the confidence, valid
  UTF-8, marshals to JSON. Parsers have their own byte-level fuzz targets.
- **Hostile servers** (`e2e/robustness_test.go`): every fingerprinter against
  silent, slow-drip (one byte every 20 ms forever), garbage and closing
  servers must return in bounded time without matching; concurrent use of one
  instance under `-race`; prompt cancellation; no goroutine leaks.
- **Cross-protocol matrix** (`e2e/crossmatrix_test.go`): every fingerprinter
  against a minimal correct speaker of every other protocol — each speaker is
  detected as its own protocol and by no other.
- **Interop** (`make interop`): detection and identity against the pinned,
  published reference servers of the `*-interop` suites.

## Documentation

- [API.md](API.md) — every exported type and function
- [ARCHITECTURE.md](ARCHITECTURE.md) — engine, sessions and the scoring path
- [FINGERPRINTS.md](FINGERPRINTS.md) — per-protocol probes, bytes and confidence
- [ERRORS.md](ERRORS.md) — the error taxonomy
- [OBSERVABILITY.md](OBSERVABILITY.md) — logging, the Observer and tracing
- [INTEROPERABILITY.md](INTEROPERABILITY.md) — the reference servers and how they are pinned
- [LIMITATIONS.md](LIMITATIONS.md) — what the probes do not cover
- [cmd/otprobe/README.md](cmd/otprobe/README.md) — the CLI: commands, exit codes, JSON output
- [SECURITY.md](SECURITY.md) — safe use in OT networks and reporting issues
- [CONTRIBUTING.md](CONTRIBUTING.md) · [RELEASE.md](RELEASE.md)

## License

MIT — see [LICENSE](LICENSE).
