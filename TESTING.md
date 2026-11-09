# Testing go-otfp

How to run each tier. Peers and images are in [INTEROPERABILITY.md](INTEROPERABILITY.md).

## Tiers

| Tier | Command | Prerequisites | In CI |
|---|---|---|---|
| Unit | `make test`, `make test-race` | none | yes, Go 1.26 and 1.27 |
| End-to-end | `make e2e` (`e2e/`) | none | yes, in the test matrix |
| Stress | `make stress` (`STRESS`, default 10 shuffled race runs) | none | nightly |
| Fuzz | `make fuzz` (`FUZZTIME`, default 20s) | none | yes, 10s per target; nightly 5m per target |
| Interop | `make interop` | Docker | nightly, with `OTFP_REQUIRE_INTEROP=1` |
| Cross-compile | `make cross` | none | no |
| Generated code | `make generate-check` | none | no |

`make bench` exists, but the repository has no `Benchmark` functions yet.

The end-to-end tier (`e2e/`) drives the public engine against scripted servers on loopback TCP (`internal/testsrv`). `TestEngineScanFindsTheSpeaker` scans each speaker through `ParseTarget` and the default fingerprinters. `TestCrossProtocolMatrix` runs every TCP fingerprinter against a speaker of each of eight protocols, in detect and identify mode; `TestHostileServersBounded` checks that a hostile server cannot hold a probe past its limits.

Chaos and safety tests run in the unit and end-to-end tiers, with no extra prerequisites:

- `internal/chaos` wraps loopback TCP and UDP speakers with seeded, deterministic faults: one-byte and random fragmentation, delays, duplicates, bit flips, truncation, resets and stalls; for UDP drops, duplicates, reordering, bounded floods of spoofed datagrams, empty and oversized datagrams, answers from another port, and an ICMP-refused port.
- Each protocol package's `TestChaos` runs its fingerprinter under every fault in detect and identify mode. It checks that the fingerprinter never panics, hangs past its timeout or leaks goroutines or file descriptors; that a fragmented but complete answer still matches; and that a cut answer never scores high.
- Each package's `TestSafetyContract` records every byte the fingerprinter sends and asserts that only the operations FINGERPRINTS.md documents are used, at each intrusiveness level (for example Modbus FC 43/14 and, read-only, FC 03; never a write or control code).
- `e2e/dialer_test.go` scans a live TCP and UDP speaker through a `Dialer` that refuses every address, sequentially and in parallel: no fingerprinter may match, and each result carries the dialer's error, so a fingerprinter that dialled around it fails the test. `TestClientSideFaultsThroughDialer` wraps the client's own connection in `internal/chaos` through the dialer (duplicates, bit flips, truncation, resets of its requests) and checks every TCP fingerprinter's result contract, time bound and certainty against each speaker. Stalls are not in that list: on the client side they would hold the wrapper, not the library, past its deadlines.
- In `e2e/`, `TestCrossProtocolMatrixUnderChaos`, `TestEchoIsNoProtocol`, `TestEngineHonoursMaxIntrusiveness`, `TestPassiveScanSendsNoReadOnlyStep` and `TestUDPHostile` do the same across protocols.

## Environment variables

| Variable | Effect |
|---|---|
| `OTFP_REQUIRE_INTEROP` | `1` fails on a missing interop prerequisite instead of skipping |
| `OTFP_INTEROP_ADAPTERS` | Runs the named adapters only |
| `OTFP_<PROTOCOL>_IMAGE` | Replaces the pinned image of one adapter |

Images that need fixtures or a PKI are skipped when the sibling `*-interop` repositories are not checked out beside go-otfp ([LIMITATIONS.md](LIMITATIONS.md)). `OTFP_REQUIRE_INTEROP=1` turns those skips, and a missing Docker, into failures; the nightly workflow sets it and checks the siblings out.

## Coverage

`make coverage` measures `COVER_PKGS` and fails below `COVER_MIN` (90), the same minimum as `coverage-min` in `.github/workflows/ci.yml`; `make coverage-check` is its alias. `make coverage-pkg-check` then holds every package to `COVER_PKG_MIN` (90; lowest measured 92.6 %, `protocols/openadr`) and prints the per-package figures; CI's Per-package coverage job runs it. `make coverpkg-check` keeps `COVER_PKGS` equal to CI. Excluded: `cmd/`, `internal/cmd`, the test helpers `internal/testsrv` and `internal/fuzzkit`, the end-to-end suite and the examples.

## Fuzz regressions

`make fuzz` discovers the targets under `protocols/` and `internal/iso`, `internal/mbap`. A failing input is written to `testdata/fuzz/<target>/` of the package. Commit it with the fix: `go test` replays it from then on.
