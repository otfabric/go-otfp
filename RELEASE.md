# go-otfp Releases

> **Stability:** `v0.x` is pre-1.0. Public APIs may change between minor
> tags; pin versions and read these notes before upgrading.

## v0.5.1

**Date:** 2026-11-07
**Previous release:** v0.5.0

### Changed

- The bundled command-line tools are built on v0.5.0. Library code is the same as v0.5.0.

---

## v0.5.0

**Date:** 2026-11-07
**Previous release:** v0.4.0

### Changed

- `otprobe version` prints the organisation's one-line format: `otprobe 0.5.0 (tag v0.5.0, commit <full sha>, built <RFC 3339 UTC>, go1.26.3, linux/amd64)`. The version has no leading `v`; the `tag …,` part appears only for a release build; the commit is the full SHA. A build without release ldflags reports `dev` (the module version for `go install …@vX.Y.Z`; a pseudo-version or `+dirty` version is `dev`), the commit from the Go build information (`-dirty` for a modified tree) and `built unknown`.
- `otprobe version --format json` is one line with the keys `name`, `version`, `tag`, `commit`, `built`, `libraries`, `go`, `platform` in that order (`libraries`: the other OT Fabric `go-*` libraries the binary is built on, `[]` today; in text they follow `built …`) (was an indented object with `version`, `commit`, `buildDate`, `go`, `platform`). `--format table` (for example from `OTPROBE_OUTPUT_FORMAT=table`) prints the text line instead of failing.
- `make build` injects the full commit SHA and an RFC 3339 build date, and the version (without `v`) and tag only when HEAD is exactly on a tag; otherwise the binary reports `dev`.

### Added

- `otprobe version --json`, the same as `--format json`.
- Shell completion completes `version --format` and `--json`; a test fails when a flag that takes a value has no completion. The README has one Shell completion section for bash, zsh, fish and PowerShell.

The library is unchanged.

---

## v0.4.0

**Date:** 2026-11-07
**Previous release:** v0.3.1

### Breaking

- `otprobe` exit codes converge on the OT Fabric organisation table (engineering `standards/api-design.md`; [cmd/otprobe/docs/exitcodes.md](cmd/otprobe/docs/exitcodes.md)). Old → new:
  - interrupted by SIGINT/SIGTERM: `10` → `130`; the JSON error `kind` is `interrupted` (was `internal`), `code` still `context_canceled`.
  - every probe failed with an I/O error other than a refusal or timeout (connection reset, TLS handshake failure): `1` → `4` (`5` → `4` when the others timed out).
  - `--deadline` ended the scan before anything matched or answered: `1` → `5`.
  - every fingerprinter failed unexpectedly (a panic the engine reports): `1` → `10`.
  - text or `list` output that could not be written: the scan's outcome code (usually `0`) → `10`.
  - `0` success, `1` findings (no match), `2` usage, `3` invalid input, `4` transport, `5` timeout and `7` partial are otherwise unchanged.

### Changed

- `otprobe` takes its root context from `signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)` and passes it to every command.

---

## v0.3.1

**Date:** 2026-11-05
**Previous release:** v0.3.0

### Changed

- The bundled `otprobe` is built on v0.3.0: it detects and identifies KNXnet/IP, MQTT, Sparkplug B and CANopen (CiA 309-3 gateways), and lists and completes their slugs. Library code is the same as v0.3.0.
- `otprobe detect --tls` uses the library's TLS fingerprinting configuration (`internal/tlsx`, TLS 1.2 minimum, certificates not verified, as before).
- `--path` help now says what it does: the WebSocket path OCPP tries first (IEEE 2030.5 and OpenADR ignore it).

### Added

- `otprobe detect --canopen-node N` (1 to 127): the CANopen node whose identity is read through a CiA 309-3 gateway in `--identify` mode; out-of-range values exit 3 (`invalid_flag_combination`). Without it the gateway's default node is used, which CANopenNode does not set.

---

## v0.3.0

**Date:** 2026-11-05
**Previous release:** v0.2.2

### Added

- **KNXnet/IP** (`knx`, UDP and TCP 3671): DESCRIPTION_REQUEST with a route-back HPAI; identity from the description (friendly name, medium, individual address, serial, MAC, service families, Secure/Tunnelling v2/Routing variant). Validated against calimero-server and knxd.
- **MQTT** (`mqtt`, TCP/TLS 1883/8883): 3.1.1 CONNECT/CONNACK and PINGREQ, MQTT 5 retry on the standard ports; identify reads the MQTT 5 CONNACK properties and, when read-only probes are allowed, `$SYS/broker/version`. Validated against Mosquitto and HiveMQ CE.
- **Sparkplug B** (`sparkplugb`, read-only, refines MQTT): QoS 0 subscriptions to STATE and `spBv1.0` topics for a bounded window; reports host applications, groups, edge nodes, devices and NBIRTH metrics. Never publishes. Validated against Sparkplug host and edge references on both brokers.
- **CANopen** (`canopen`, CiA 309-3 ASCII gateways over TCP): `info version` with an echoed sequence number; identify reads the node's 0x1018/0x1000/0x1008/0x100A over SDO when read-only probes are allowed (`canopen.Config.Node`). Validated against CANopenNode canopend.
- `core.ProtocolKNX`, `ProtocolMQTT`, `ProtocolSparkplugB` and `ProtocolCANopen` (values 15 to 18).
- Interop suite: KNX, MQTT, Sparkplug B and CANopen adapters (CANopen needs a Linux Docker host with vcan); images pinned to the latest interop releases.

### Fixed

- An echo of the probe was taken for the protocol: Modbus (certain), EtherNet/IP, OPC UA, PROFINET and DNP3. EtherNet/IP was certain without the echoed sender context.
- UDP: one spoofed, empty, oversized or foreign datagram before the answer made BACnet, PROFINET, EtherNet/IP and KNX report no match. The exchange now waits for the real answer; a UDP service of another protocol costs one retransmission window.
- Windows: refused connections were never reported as refused (so `StopOnRefused` never fired), and oversized or ICMP-reset UDP reads aborted the exchange.
- OpenADR 2.0b: the registration POST did not send its body, so VTNs that read it were not detected.
- IEEE 2030.5: an endless or 16 MiB handshake flight was not bounded; a CCM_8 flight cut before ServerHelloDone scored high. ClientHello lengths wrapped for server names of 64 KiB or more; SNI is now sent only for host names of 1 to 253 octets.
- BACnet: an I-Am vendor ID wider than 32 bits was truncated.
- DNP3: `Frame` wrapped its length past 250 octets of user data (it now panics, as for any frame the probes cannot build).
- MMS: a calling or called TSEL over 241 octets in total produced a malformed COTP CR (Detect now returns a DetectError before dialling); BER lengths of 64 KiB or more were encoded wrongly.
- SunSpec: identify with base 0xFFFE wrapped to register 0; a cancellation between reads was reported as a clean no match.
- CAN: a version reply cut before its terminator scored high.
- IEC 104: `Framer(nil)` panicked.
- DNP3: identify against a peer that drips frames could take up to 32 timeouts; it is now bounded at 3 × the timeout, keeps what it read and says it was cut short.
- SunSpec and Sparkplug B: a direct `Detect` call with passive-only options (the zero `core.Options`) read registers or subscribed; they now send nothing unless read-only probes are allowed (the engine already skipped them).

### Changed

- **Go 1.26 or later** (CI: Go 1.26 and 1.27); `go fix` applied.
- The one TLS configuration that does not verify certificates is `internal/tlsx` (TLS 1.2 minimum, as before). SAST (gosec, opengrep) 60 findings to 1, which is that configuration, recorded as accepted risk.
- New chaos (`internal/chaos`), hostile-peer and safety-contract tests in every protocol package and in `e2e/`.
- The bundled command-line tools are built on v0.2.2.

---

## v0.2.2

**Date:** 2026-10-31
**Previous release:** v0.2.1

### Changed

- The bundled command-line tools are built on v0.2.1. Library code is the same as v0.2.1.

---

## v0.2.1

**Date:** 2026-10-31
**Previous release:** v0.2.0

### Changed

- Policy 1.2: build output in `bin/` and `release/`, a per-package coverage floor, and more tests and CI. No change in behaviour.

---

## v0.2.0

**Date:** 2026-10-30
**Previous release:** v0.1.0

### Changed

- **`cmd/otprobe` is now a nested module** (`github.com/otfabric/go-otfp/cmd/otprobe`,
  ADR-0009). The library's `go.mod` no longer requires cobra, so consumers stop
  inheriting it. Library import paths and the exported API are unchanged.
  - Release binaries are published as before.
  - Build from a checkout with `make build`, or `cd cmd/otprobe && go build .`.
  - `go install github.com/otfabric/go-otfp/cmd/otprobe@<version>` works up to
    v0.1.0 and not after it, while the nested module's `replace` is in place.

---

## v0.1.0

**Date:** 2026-10-27
**Previous release:** v0.0.3

### Summary

Complete rewrite of the library around a new engine and a transport-aware,
graded-confidence fingerprinting model, expanding coverage from 10 to 14 OT
protocols and adding read-only device identification. Still `v0.x` (pre-1.0);
the public API changed substantially — review before upgrading.

### Added

- **Four protocols:** SunSpec (on Modbus), OCPP (WebSocket), IEEE 2030.5
  (mutual-TLS shape + `/dcap`) and OpenADR (3 and 2.0b).
- **Identify mode** (`core.ModeIdentify`, `otprobe --identify`): each protocol's
  standard read-only identity request fills a structured `core.Identity`
  (vendor, product, model, version, serial, name, attributes).
- **UDP and TLS probing:** BACnet/IP and PROFINET are now fingerprinted over
  UDP (previously, incorrectly, over TCP), EtherNet/IP over both TCP and UDP
  ListIdentity, and any TCP probe can run over TLS via `Target.TLS` or
  `tls://`.
- **Graded confidence** on a shared scale, with inspectable `Evidence` and a
  stable `Fingerprint` signature per result; `Variant` distinguishes
  S7comm-plus, OCPP versions, OpenADR versions and the like.
- **Port-aware engine:** probes the target port's likely protocols first,
  early-stops on a confident match (while still running refinements such as
  SunSpec over Modbus), stops a TCP scan on a refused port, and supports
  parallel scanning, pacing and a conservative `SafeEngineConfig`.
- **`otprobe` rewrite:** `detect <target>` with schemes, a sweep of the
  well-known ports for a bare host (`--ports` for a list), `--identify`,
  `--safe`, `--protocol`/`--exclude`, `--path`, `--trace`, `--debug`; `list`,
  `version` and `completion bash|zsh|fish|powershell` (commands, flags and
  flag values: protocols, formats, networks, ports, schemes). Text output by
  default; `--format table|json` on every command, with a versioned JSON
  schema ([cmd/otprobe/docs/json-output.md](cmd/otprobe/docs/json-output.md)) and fatal errors as one
  JSON object. Exit codes follow the OT Fabric CLI convention: 0 detected, 1
  no match, 2 usage, 3 invalid input, 4 unreachable, 5 timeout, 7 partial, 10
  interrupted ([cmd/otprobe/docs/exitcodes.md](cmd/otprobe/docs/exitcodes.md)).
- **Examples:** runnable programs in `examples/` (quickstart, identify,
  sweep, custom fingerprinter, observability) that work offline against a
  demo device, `Example` functions for pkg.go.dev, and a CLI reference with
  real output for every protocol ([cmd/otprobe/docs/cli.md](cmd/otprobe/docs/cli.md)).
- **Bug-hunting test suite:** end-to-end fuzzing of every fingerprinter
  (`FuzzDetect`, checking the Fingerprinter contract on every result),
  hostile-server tests (silent, slow-drip, garbage, closing), concurrent use
  of one instance under `-race`, prompt-cancellation and goroutine-leak
  checks, a cross-protocol false-positive matrix, and `make stress`. Library
  coverage is 98% (every package ≥ 92%), and `make coverage` fails below 90%.
- **Interop suite** (`interop/`, build tag `interop`): detection and identity
  checked against 11 pinned, published reference servers of the `*-interop`
  suites, including both IEEE 2030.5 servers (GridAPPS-D, Envoy).
- **Generated CIP catalogue:** EtherNet/IP vendor and device-type names are
  generated from `go-ethernetip` (`internal/cmd/gencip`), keeping the library
  dependency-free.

### Changed

- New package layout: `core` (engine, registry, result model, typed errors),
  `internal/{wire,iso,mbap,httpx,fpx}`, one package per protocol, `cmd/otprobe`.
- `core.Protocol` is a slug-and-name type with text marshalling and aliases;
  numeric values are stable and append-only.
- Fingerprinters now declare themselves with `core.Info` (transport, ports,
  priority, intrusiveness, refines) and implement `Detect(ctx, target, opts)`.

### Fixed (found by the review and the bug-hunting suite)

- **Cancellation:** a scan cancelled before a step armed its deadline waited
  out the full timeout on every remaining step (the step's own deadline
  overrode the one set on cancellation); the scan's overall deadline did not
  cap per-operation timeouts.
- **Parallel engine:** an early stop cancelled refinements of the matched
  protocol (SunSpec after Modbus) and reported the probes it cancelled
  itself as error results.
- **BACnet identify:** all property reads shared one invoke ID, so a late or
  duplicated answer was taken for the next property (the object name read as
  the vendor name). Reads now use distinct invoke IDs and match answers by
  invoke ID and property; EtherNet/IP over UDP and PROFINET discard replies
  carrying another sender context or activity UUID.
- **HTTP-based probes** (OpenADR, OCPP, IEEE 2030.5) read only the first TCP
  segment, losing bodies sent separately, chunked or close-delimited.
- **OPC UA identify** sent a zero RequestHeader timestamp, which open62541
  (correctly) refuses with BadInvalidTimestamp.
- **Contract:** OCPP, SunSpec and CAN returned an error for a reply that is
  merely not their protocol (a close, garbage, a Modbus mismatch); DNP3 kept
  reading after a malformed frame and waited out the timeout; a short reply
  to a length-framed probe cost the whole timeout instead of an idle gap.
- **OpenADR** was skipped by `--safe` although its OpenADR 3 probes are
  passive GETs; it is passive now, with the 2.0b POST gated on read-only.
- **CLI:** `otprobe detect <host>` without a port, documented as a sweep,
  failed; `-o json` usage errors were rendered as text.
- **IEEE 2030.5:** a server offering only CCM_8 (GridAPPS-D) was never
  recognised: the probe matched an error text that only a Go *server*
  produces. The fingerprinter now sends its own TLS 1.2 ClientHello and
  reads the server's flight (chosen suite, certificate, certificate
  request), and detects GridAPPS-D and Envoy.
- **BACnet:** SimpleACK replies lost their invoke ID and were discarded.
- **S7comm:** when every TSAP attempt was closed by the peer, the probe went
  on with the last, closed session and reported a false ISO-on-TCP hint.

### Removed

- The vendored Wireshark dissector sources (`wireshark/`, GPL-licensed) are no
  longer part of the module; the protocol references live in `FINGERPRINTS.md`.

---

## v0.0.3

**Date:** 2026-07-30
**Previous release:** v0.0.2

## Summary

Patch release: MIT open-source hygiene, fix docs/code mismatches, wire typed
detection errors into detectors, and harden the Makefile coverage target.
Still `v0.0.x` (pre-1.0).

## Changes

### License & open-source hygiene

- **LICENSE** — Normalized copyright to `Copyright (c) 2026 OT Fabric` (was personal name); standard MIT text retained.
- **SPDX headers** — Added `// SPDX-License-Identifier: MIT` to all first-party `.go` source files (55 files).
- **README** — License section normalized to point at [LICENSE](./LICENSE).
- **README badges** — Standardized block: Go `1.23+` (from `go.mod`), pkg.go.dev, License, CI, Codecov (tokenless `codecov.io/gh/...`), Release (`label=release`). Removed Go Report Card (service unmaintained).

### Fixed

- **README CI badge** — image URL pointed at `otfp/modbus`; now `otfabric/go-otfp`.
- **`DefaultEngineConfig` docs** — `Parallel` default documented as `false` (matches code / CLI).
- **Makefile `coverage`** — define `TEST_PKGS` (all packages except `/cmd/`) so coverage no longer expands to an empty package list.

### Added

- **`core.ClassifyDial` / `ClassifyIO`** — map dial and send/receive failures to `TimeoutError`, `ConnectionError`, or `DetectError`.
- All protocol detectors now return those typed errors instead of bare `fmt.Errorf` wrappers (so `otprobe` JSON classification and `errors.As` work).
- **Makefile `vuln`** — `govulncheck ./...`, included in `make check`.
- **Makefile** — `GOWORK=off` so a parent `go.work` that omits this module does not break checks.

### Documentation

- **Observer** — clarified as scan progress/audit callbacks, not request metrics (README, API.md, godoc).
- **Stability** — `v0.0.x` pre-1.0 note in README and this file.
- **Errors** — document classifier helpers; note `InvalidResponseError` remains optional (detectors prefer `NoMatch` for protocol mismatches).
- **README** — table of contents; short **Project structure** summary; Architecture tree refreshed (`classify.go`, `wireshark/`, removed stale `version.txt`).
- **ERRORS.md** — Short error taxonomy: no-match `Result` vs typed transport/detection errors; classifier helpers; CLI JSON type mapping.

---

## v0.0.2

**Date:** 2026-03-24
**Previous release:** v0.0.1

### Summary

Module rename, build system overhaul, and adoption of shared CI/release workflows.

### Changes

**Module rename**
- Renamed Go module from `github.com/otfabric/otfp` to `github.com/otfabric/go-otfp` across all packages, imports, and documentation.

**Build-time version injection**
- Replaced `version.txt`-based versioning with compile-time ldflags (`-X main.version`, `-X main.tag`, `-X main.commit`, `-X main.buildDate`).
- Removed `cmd/otprobe/version.txt`.
- Updated `BuildInfo` struct: replaced `Branch`, `Revision`, and `BuildUser` fields with `Tag` and `Commit` to align with the shared release workflow.

**CI/CD**
- Migrated CI workflow to reusable `otfabric/.github/.github/workflows/go-ci.yml@v2` with multi-version Go matrix (1.23–1.26) and Codecov integration.
- Migrated release workflow to reusable `go-package-release.yml@v2` and `go-binary-release.yml@v2`, replacing the monolithic inline release job.

**Makefile**
- Restructured targets: separated `fmt`, `lint` (staticcheck), `lint-ci` (golangci-lint), and added `coverage`/`cover` targets.
- Version variables now derived from `git describe` and `git rev-parse` instead of `version.txt`.
- Binary output directory remains `./bin/`.

**Go version**
- Lowered minimum Go version from 1.25 to 1.23.

**Documentation**
- Updated README badges, install commands, and code examples to reflect the new module path.

---

## v0.0.1

**Date:** 2026-03-12
**Previous release:** N/A

## Summary

- Initial release
