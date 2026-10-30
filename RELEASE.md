# go-otfp Releases

> **Stability:** `v0.x` is pre-1.0. Public APIs may change between minor
> tags; pin versions and read these notes before upgrading.

## Unreleased

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
  schema ([docs/json-output.md](docs/json-output.md)) and fatal errors as one
  JSON object. Exit codes follow the OT Fabric CLI convention: 0 detected, 1
  no match, 2 usage, 3 invalid input, 4 unreachable, 5 timeout, 7 partial, 10
  interrupted ([docs/exitcodes.md](docs/exitcodes.md)).
- **Examples:** runnable programs in `examples/` (quickstart, identify,
  sweep, custom fingerprinter, observability) that work offline against a
  demo device, `Example` functions for pkg.go.dev, and a CLI reference with
  real output for every protocol ([docs/cli.md](docs/cli.md)).
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
