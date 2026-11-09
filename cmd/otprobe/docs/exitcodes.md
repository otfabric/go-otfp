# Process exit codes

`otprobe` uses stable exit codes for scripting: the OT Fabric organisation
exit-code table (engineering `standards/api-design.md`), as the `*ctl` tools
use it. A fatal error is rendered once: as one `error:` line on stderr, or,
with `--format json` (or `OTPROBE_OUTPUT_FORMAT=json`), as a single JSON
`error` object on stdout. That holds for usage errors too: `otprobe` reads
`--format`/`-o` from the raw command line even when the rest of it does not
parse.

| Code | Meaning |
|------|---------|
| 0 | Success (`ok`), detected: a protocol matched at high confidence (≥ 0.90) on at least one scanned port |
| 1 | Findings, no match: the scan completed; the target answered, but no protocol matched |
| 2 | Usage (`usage`): unknown command or flag, a missing or extra argument, a value a flag cannot hold, an unknown shell for `completion` |
| 3 | Invalid input (`invalid_input`): a target, protocol name, format, flag value (`--proxy`, `--source-addr`) or flag combination (`--proxy` with UDP) that does not make sense. Nothing was sent |
| 4 | Transport: nothing answered and the target (or the `--proxy`) refused, could not be reached, reset the connection, or failed the TLS handshake |
| 5 | Timeout: nothing answered in time, or `--deadline` ended the scan before anything matched |
| 7 | Partial: a protocol matched, but below the high-confidence threshold (a valid result was written) |
| 10 | Internal (`output`, `internal`): the result could not be written, or a fingerprinter failed unexpectedly |
| 130 | Interrupted (`interrupted`): SIGINT or SIGTERM before a result was written |

**Precedence.** A scan's outcome is the best across all scanned ports and
probes: detected, then partial, then no match (something answered), then
transport (something refused or failed), then timeout, then internal. One
open, matching port makes a sweep exit `0` however many ports were closed.

**Changed in v0.4.0.** `otprobe` converged on the organisation table:

| Old | New | Condition |
|-----|-----|-----------|
| 10 | 130 | interrupted by SIGINT/SIGTERM (JSON `kind` `internal` → `interrupted`) |
| 1 | 4 | every probe failed with an I/O error other than a refusal or timeout (connection reset, TLS handshake failure); `5` → `4` when the other probes timed out |
| 1 | 5 | `--deadline` ended the scan before anything matched or answered |
| 1 | 10 | every probe's fingerprinter failed unexpectedly (a panic, reported by the engine) |
| 0, 1, 4, 5, 7 | 10 | text or list output could not be written: the scan's outcome code was returned (only JSON and table write failures were caught before) |

Codes 0, 1, 2, 3, 4, 5 and 7 are otherwise unchanged.

**JSON error object.** `kind` drives the exit code; `code` is stable for
machines. Do not parse `message`.

```json
{"error": {"kind": "invalid_input", "code": "invalid_protocol", "message": "unknown protocol \"modbuz\" (see otprobe list)"}}
```

| `kind` | `code` values |
|--------|---------------|
| `usage` | `invalid_input` |
| `invalid_input` | `invalid_input`, `invalid_target`, `invalid_protocol`, `invalid_format`, `invalid_flag_combination`, `no_fingerprinters` |
| `output` | `output_write_failed` |
| `internal` | `internal_unexpected` |
| `interrupted` | `context_canceled` |

Per-probe failures (a refused port, a timeout) are not fatal: they are part
of the result, in the text output and in the JSON `results[].error`, and the
exit code reflects them as above.
