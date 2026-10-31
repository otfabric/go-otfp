# Testing go-otfp

How to run each tier. Peers and images are in [INTEROPERABILITY.md](INTEROPERABILITY.md).

## Tiers

| Tier | Command | Prerequisites | In CI |
|---|---|---|---|
| Unit | `make test`, `make test-race` | none | yes, Go 1.23 to 1.26 |
| End-to-end | `make e2e` (`e2e/`) | none | yes, in the test matrix |
| Stress | `make stress` (`STRESS`, default 10 shuffled race runs) | none | nightly |
| Fuzz | `make fuzz` (`FUZZTIME`, default 20s) | none | yes, 10s per target; nightly 5m per target |
| Interop | `make interop` | Docker | nightly, with `OTFP_REQUIRE_INTEROP=1` |
| Cross-compile | `make cross` | none | no |
| Generated code | `make generate-check` | none | no |

`make bench` exists, but the repository has no `Benchmark` functions yet.

The end-to-end tier (`e2e/`) drives the public engine against scripted servers on loopback TCP (`internal/testsrv`). `TestEngineScanFindsTheSpeaker` scans each speaker through `ParseTarget` and the default fingerprinters. `TestCrossProtocolMatrix` runs every TCP fingerprinter against a speaker of each of eight protocols, in detect and identify mode; `TestHostileServersBounded` checks that a hostile server cannot hold a probe past its limits.

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
