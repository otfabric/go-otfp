# Architecture

How a scan flows from a `Target` to a `Report`, and why the pieces are shaped
the way they are.

## Layers

```
otfp.DefaultEngine()          convenience: registry + engine
        │
core.Engine                   orchestration: planning, ordering, early stop
        │  core.Options (mode, trace, intrusiveness, logger)
core.Fingerprinter            one per protocol (protocols/<name>)
        │  internal/fpx.Builder   evidence → confidence → Result
internal/wire.Session         framed TCP/TLS/UDP I/O, error classification
        │
internal/{iso,mbap,httpx}     shared wire formats (COTP/TPKT, MBAP, HTTP)
```

The library core depends only on the Go standard library. The CLI adds cobra.

## The engine

`Engine.Scan` validates the target, builds a **plan** from the registry, runs
it, sorts the results and picks the best.

- **Planning** keeps only the fingerprinters of the target's transport,
  removes those filtered out by `Protocols`/`Exclude` or above
  `MaxIntrusiveness`, and orders them: those whose well-known ports include
  the target port first (so a scan of `:502` tries Modbus and SunSpec before
  the rest), then the others, each group by `Priority`. `LikelyOnly` keeps
  only the port-matching group.
- **Running** is sequential by default — many field devices accept a single
  TCP connection at a time, so concurrent probes give non-deterministic
  results. `Parallel` with `MaxConcurrency` is available for hosts that
  tolerate it. `MinInterval` paces probe starts to stay under IDS thresholds.
- **Early stop** halts after the first result at or above
  `HighConfidenceThreshold`, except that a *refining* fingerprinter (SunSpec
  refines Modbus) still runs and is preferred as the best match on a tie.
- **Stop on refused** ends a TCP scan when a connection is refused: nothing
  listens on the port, so no other TCP fingerprinter can succeed.
- **Resilience** — each `Detect` runs under a panic recovery, so one broken
  fingerprinter becomes an error result instead of taking the scan down. The
  `Observer` and `Logger` receive progress without affecting results.

`best()` chooses the matched result with the highest confidence; among equal
confidences a refining protocol beats the one it refines.

## Fingerprinters

A `Fingerprinter` describes itself with `Info` (protocol, transport,
well-known ports, priority, intrusiveness, what it refines, a one-line probe
description) and implements `Detect`. Detect opens a `wire.Session`, exchanges
the protocol's probes, and scores the replies with an `fpx.Builder`, which
accumulates evidence, the fingerprint signature and the identity, and emits
the `Result`. The contract: a non-nil error means *could not decide*; a reply
that is simply the wrong protocol is a `NoMatch` with a nil error.

## Sessions (`internal/wire`)

A `Session` wraps a dialled TCP, TLS or UDP connection and provides:

- **Framed reads** — a `Framer` tells a read when a whole protocol frame has
  arrived, so detection does not rely on one `Read` returning a complete
  message; bytes past the frame are kept for the next read.
- **UDP round-trips** with retransmission for lossy datagram protocols.
- **Error classification** — dial and I/O failures become `TimeoutError`,
  `ConnectionError` or `DetectError`, and `ErrClosed` marks a peer that
  closed without answering.
- **Context cancellation** — a cancelled scan unblocks pending I/O.
- **Tracing** — every probe/response pair is recorded when `Options.Trace`
  is set, surfacing in `Result.Exchanges`.

## Shared wire formats

`internal/iso` (TPKT + COTP) is shared by MMS and S7; `internal/mbap` (Modbus
MBAP framing) by Modbus and SunSpec; `internal/httpx` (one HTTP/1.1
request/response over a session) by OCPP, IEEE 2030.5 and OpenADR.
`internal/fpx` holds the scoring helper and the confidence scale.

## Generated data

The EtherNet/IP vendor and device-type name tables
(`protocols/enip/catalog.go`) are generated from the CIP catalogue of the
sibling `go-ethernetip` module by `internal/cmd/gencip` (`make generate`), so
go-otfp stays dependency-free while the names stay accurate.
