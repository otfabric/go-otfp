# Testing go-otfp

How to run each tier. Peers and images are in [INTEROPERABILITY.md](INTEROPERABILITY.md).

## Tiers

| Tier | Command | Prerequisites | In CI |
|---|---|---|---|
| Unit | `make test`, `make test-race` | none | yes, Go 1.26 and 1.27 |
| End-to-end | `make e2e` (`e2e/`) | none | yes, in the test matrix |
| Stress | `make stress` (`STRESS`, default 10 shuffled race runs) | none | nightly |
| Fuzz | `make fuzz` (`FUZZTIME`, default 20s) | none | yes, 10s per target; nightly 5m per target |
| 32-bit | `GOARCH=386 go test -count=1 ./...` | a Linux amd64 host (it runs 386 binaries) | nightly, without `-race` (the race detector does not exist for 386) |
| Interop | `make interop` | Docker | nightly, with `OTFP_REQUIRE_INTEROP=1` |
| Cross-compile | `make cross` | none | no |
| Generated code | `make generate-check` | none | no |

`make bench` exists, but the repository has no `Benchmark` functions yet.

The end-to-end tier (`e2e/`) drives the public engine against scripted servers on loopback TCP (`internal/testsrv`). `TestEngineScanFindsTheSpeaker` scans each speaker through `ParseTarget` and the default fingerprinters. `TestCrossProtocolMatrix` runs every TCP fingerprinter against a speaker of each of eight protocols, in detect and identify mode; `TestHostileServersBounded` checks that a hostile server cannot hold a probe past its limits.

Chaos and safety tests run in the unit and end-to-end tiers, with no extra prerequisites:

- `internal/chaos` wraps loopback TCP and UDP speakers with seeded, deterministic faults: one-byte and random fragmentation, delays, duplicates, bit flips, truncation, resets and stalls; for UDP drops, duplicates, reordering, bounded floods of spoofed datagrams, empty and oversized datagrams, answers from another port, and an ICMP-refused port.
- Each protocol package's `TestChaos` runs its fingerprinter under every fault in detect and identify mode. It checks that the fingerprinter never panics, hangs past its timeout or leaks goroutines or file descriptors; that a fragmented but complete answer still matches; and that a cut answer never scores high.
- Each package's `TestSafetyContract` records every byte the fingerprinter sends and asserts that only the operations FINGERPRINTS.md documents are used, at each intrusiveness level (for example Modbus FC 43/14 and, read-only, FC 03; never a write or control code).
- `e2e/dialer_test.go` scans a live TCP and UDP speaker through a `Dialer` that refuses every address, sequentially and in parallel: no fingerprinter may match, and each result carries the dialer's error, so a fingerprinter that dialled around it fails the test. `TestClientSideFaultsThroughDialer` wraps the client's own connection in `internal/chaos` through the dialer (duplicates, bit flips, truncation, resets of its requests) and checks every TCP fingerprinter's result contract, time bound and certainty against each speaker. Stalls are not in that list: on the client side they would hold the wrapper, not the library, past its deadlines. `TestStalledDialerIsBoundedByTheTimeout` covers a proxy that never answers: a dialer that blocks until its context ends must give every fingerprinter a timeout error within its timeout, and a cancelled scan returns at once. `TestEngineClosesEveryDialedConnection` counts the connections the dialer hands out across TCP and UDP speakers, sequential, parallel and cancelled scans: the library must close each one, with no goroutine or file-descriptor leak.
- In `e2e/`, `TestCrossProtocolMatrixUnderChaos`, `TestEchoIsNoProtocol`, `TestEngineHonoursMaxIntrusiveness`, `TestPassiveScanSendsNoReadOnlyStep` and `TestUDPHostile` do the same across protocols.
- Leaks are checked by one helper, `chaos.Snapshot` and `Baseline.Check` (`internal/chaos/leaks.go`). It compares the goroutines that exist, by identifier, with those of the snapshot, waits up to 3 s for goroutines that are ending, and reports each goroutine that stays with its stack. A goroutine that stays while another one ends is reported, which a count would miss (`TestLeakedNamesTheGoroutineThatStays`). File descriptors are counted. The chaos suites, `TestNoGoroutineLeaks` and `TestEngineClosesEveryDialedConnection` use it.
- `TestScanLeavesNothingOnTheCallersContext` scans every speaker under a context that counts the functions registered on it (`context.AfterFunc`) and requires none to be left when `Scan` returns.
- `TestLimits` in each protocol package, and the tests that the resource limits table of [SECURITY.md](SECURITY.md) names, feed each limit and one more than it: a frame at the read cap and a header that declares more, the largest value a length field holds, one record, message or list entry beyond the count. They assert the outcome and an allocation budget: the octets allocated around one `Detect`, read from `runtime.MemStats` (`fuzzkit.Allocated`, `fuzzkit.Limits`). A budget is a base for what a probe allocates without reading anything, plus a few times what the limit lets it read; beyond a limit it stays far below the size the peer declared. These tests do not call `t.Parallel`: the count is the process's.
- Ownership: each constructor that stores a slice has a test that changes the caller's slice afterwards and reads the request sent (`TestBasesAreCopied`, `TestCalledTSAPsAreCopied`, `TestOutstationsAreCopied`, `TestTSELsAreCopied`, `TestEngineOwnsItsConfiguration`, `TestFiltersAreCopied`); `TestCallerWritesItsSliceDuringScans` does it from another goroutine during scans, under `-race`. The parse helpers that borrow their input have a test that pins it (`TestParseBorrowsTheASDU`, `TestParsersBorrowTheirInput`).

## Lifecycle contracts

The long-lived types are `core.Engine`, the internal `wire.Session` and the exported `mqtt.Client`, which wraps a session. An engine keeps no state between scans and has no `Close`; with `Parallel` it starts one goroutine per probe and joins them before `Scan` returns. A session, and so a client, belongs to one `Detect` call and one goroutine. There is no server, no reconnect, no queue and no background reader. The rows are those of the organisation's contract test matrix (lifecycle standard, L1 to L16).

| Row | Applies | Tests |
|---|---|---|
| L1 Close twice | MUST for `wire.Session` and `mqtt.Client`: the second call returns nil and does nothing. n/a for `Engine`, which has no `Close` | `internal/wire` `TestCloseTwice`; `protocols/mqtt` `TestClientCloseTwice`, which also checks the error of an operation after `Close` |
| L2 Two goroutines call Close | n/a: a session and a client are used from one goroutine, as their doc comments say; the scan's context is what ends their I/O from outside | |
| L3 Close during a blocked read | as cancellation of the context, the supported way | `internal/wire` `TestContextCancel`, `TestCancelBeforeOperation`, `TestDatagramCancelled`, `TestReadUntilCappedByContext`; `e2e` `TestCancellationIsPrompt`; `protocols/mqtt` `TestDetectCancelled` |
| L4 Close during a write | as cancellation; there is no shared stream | `internal/wire` `TestCancelBeforeOperation` |
| L5 Close during handshake | as a handshake that fails or stalls | `internal/wire` `TestTLSFailures`; `e2e` `TestStalledDialerIsBoundedByTheTimeout`. Not tested: a cancel in the middle of a TLS handshake, which goes through `HandshakeContext` |
| L6 Cancel a pending request | MUST | `core` `TestParallelCallerCancel`, `TestCancelledWhileWaiting`, `TestParallelEarlyStopDropsCancelled`, `TestParallelEarlyStopDropsQuietCancelled`; `protocols/mms` `TestIdentifyAfterCancel`; `e2e` `TestCancellationIsPrompt`. There is no request slot to release: one request per connection at a time |
| L7 Response after the request timed out | MUST for UDP: a late or duplicate answer is discarded by correlation, counted in the debug log, and bounded per round trip | `internal/wire` `TestRoundTripUDPDiscardsStray`, `TestDatagramVerdicts`, `TestStrayDatagramBound`, `TestStraysAreLoggedAsACount`; the UDP cases of `e2e/robustness_test.go`; each UDP package's `TestChaos` |
| L8 Response after reconnect | n/a: no reconnect | |
| L9 Callback calls a public method | MUST for `Observer`: the engine holds no lock while it calls | `core` `TestObserverCallsTheEngine` |
| L10 Callback calls Close | n/a: `Engine` has no `Close`. An observer that cancels the scan's context ends the scan | `core` `TestObserverCallsTheEngine` |
| L11 Slow callback | MUST: a callback delays its own probe only; one that does not return normally ends its probe with an error, and a `Logger` that does not return normally closes the probe's connection | `core` `TestSlowObserverDelaysItsOwnProbeOnly`, `TestObserverThatDoesNotReturnNormally`, `TestLoggerThatDoesNotReturnNormally`; `internal/wire` `TestLoggerFailureClosesSession`, `TestCancelHookRecovers`; `e2e` `TestLoggerFailureClosesEveryConnection` |
| L12 Queue at capacity | n/a: no queue. The `MaxConcurrency` semaphore has a test | `core` `TestParallelBoundedSkipsAfterStop` |
| L13 Concurrent sessions | MUST: one fingerprinter instance serves many scans at once | `e2e` `TestConcurrentUseOfOneInstance` (under `-race`); `core` `TestParallel`; `protocols/sunspec` `TestCallerWritesItsSliceDuringScans` |
| L14 Failure during construction | MUST: every connection is closed and nothing stays on the caller's context | `core` `TestOptionsDialClosesConnWithError`, `TestOptionsDialErrors`; `internal/wire` `TestTLSFailures`, `TestDialFails`; `e2e` `TestEngineClosesEveryDialedConnection`, `TestNoGoroutineLeaks`, `TestScanLeavesNothingOnTheCallersContext` |
| L15 Shutdown | n/a: no graceful shutdown | |
| L16 Close racing reconnect | n/a: no reconnect | |

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

`make fuzz` discovers the targets under `protocols/` and `internal/iso`, `internal/mbap`, `internal/httpx`. A failing input is written to `testdata/fuzz/<target>/` of the package. Commit it with the fix: `go test` replays it from then on.

## When CI runs

| Event | Workflow | What runs |
|---|---|---|
| Pull request | `pr.yml` | `docs.yml` (docsync, otfabric-policy) always; `ci.yml` unless every changed file is documentation; then `OT Fabric Required Checks` |
| Push to a branch | none | nothing; dispatch `ci.yml` to test a branch without a pull request |
| Push to `main` | `docs.yml` | the light checks; the merged commit was tested as the pull request's merge commit |
| Schedule | `nightly.yml` | the scheduled runs, on `main`: fuzz, stress, the tests on a 32-bit architecture, interop |
| Release | `release.yml` | the release workflow tests the release commit again |

Documentation means an added or modified `*.md` file outside `.github/`, `testdata/` and `vendor/`, other than `AGENTS.md` and `CLAUDE.md`. A deleted or renamed document, or any other file, runs everything. `OT Fabric Required Checks` fails unless every job that applies succeeded; its summary lists them.
