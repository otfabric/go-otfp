# Errors

go-otfp separates *"this endpoint does not speak the protocol"* from
*"detection could not reach a verdict"*. The first is an ordinary non-match
result; the second is a typed error.

## Result vs. error

`Fingerprinter.Detect` and `Engine.Detect` return `(Result, error)`:

| Outcome | `Matched` | `Confidence` | `error` / `Result.Error` |
|---|---|---|---|
| identified | true | ≥ `MatchThreshold` | nil |
| a hint | false | in (0, threshold) | nil |
| not this protocol | false | 0 | nil |
| could not decide | false | 0 | a typed error below |

In a `Report`, a per-protocol failure never fails the whole scan: it is
recorded in that result's `Error` field, and `Scan` itself returns an error
only for an invalid target or when no fingerprinter applies
(`ErrNoFingerprinters`).

A fingerprinter's error is **always a transport error** — `TimeoutError`,
`ConnectionError` or `DetectError`. A peer that closes the connection, sends
garbage or a reply that does not frame as the protocol is a NoMatch with a
nil error, never an error: it was reachable and is simply not this protocol.
The end-to-end fuzz targets and the hostile-server tests enforce this for
every built-in fingerprinter.

## Typed errors

All wrap an underlying cause (`errors.As` / `Unwrap` work) and name the
protocol and, where relevant, the address and operation.

- **`TimeoutError`** — a dial, write or read exceeded its deadline. `Op` is
  `"dial"`, `"write"`, `"read"` or `"tls"`.
- **`ConnectionError`** — a dial failed for a reason other than a timeout
  (refused, unreachable, reset, name resolution). `Refused()` reports an
  actively refused connection — nothing listens there — which ends a TCP
  scan when `StopOnRefused` is set.
- **`DetectError`** — an I/O failure during an exchange that is neither a
  timeout nor a refusal, with the failing `Op`.
- **`InvalidResponseError`** — a reply that was recognisably the protocol but
  malformed. Fingerprinters use it only where the distinction matters; most
  wrong replies are a plain non-match.
- **`ProtocolNotFoundError`** — `Engine.Detect` was asked for a protocol with
  no registered fingerprinter (for the target's transport).
- **`ErrNoFingerprinters`** — `Scan` found no applicable fingerprinter.

## Classifying transport failures

Fingerprinter authors do not build these by hand. `wire.Session` classifies
its own I/O, and the helpers `core.ClassifyDial(protocol, addr, err)` and
`core.ClassifyIO(protocol, addr, op, err)` map a raw error to the right type.
`core.IsTimeout(err)` reports whether an error is a deadline/timeout.

## In the CLI

`otprobe` maps the outcome to an exit code — `0` detected, `1` no match,
`2` usage, `3` invalid input, `4` unreachable, `5` timeout, `7` partial,
`10` interrupted or internal — and renders fatal errors as one `error:` line,
or one JSON `error` object with `--format json`. See
[docs/exitcodes.md](docs/exitcodes.md).
