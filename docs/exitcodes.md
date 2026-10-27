# Process exit codes

`otprobe` uses stable exit codes for scripting. They follow the OT Fabric CLI
convention (the `*ctl` tools), plus `1`, the outcome of a scan that found
nothing. A fatal error is rendered once: as one `error:` line on stderr, or,
with `--format json` (or `OTPROBE_OUTPUT_FORMAT=json`), as a single JSON
`error` object on stdout. That holds for usage errors too: `otprobe` reads
`--format`/`-o` from the raw command line even when the rest of it does not
parse.

| Code | Meaning |
|------|---------|
| 0 | Detected: a protocol matched at high confidence (≥ 0.90) on at least one scanned port |
| 1 | No match: the target answered, but no protocol matched |
| 2 | Usage (`usage`): unknown command or flag, a missing or extra argument, a value a flag cannot hold |
| 3 | Invalid input (`invalid_input`): a target, protocol name, format or flag combination that does not make sense. Nothing was sent |
| 4 | Transport: nothing answered and the target refused or could not be reached |
| 5 | Timeout: nothing answered in time |
| 7 | Partial: a protocol matched, but below the high-confidence threshold (a valid result was written) |
| 10 | Output / internal (`output`, `internal`): interrupted by SIGINT/SIGTERM, the result could not be written, or an unexpected error |

**Precedence.** A scan's outcome is the best across all scanned ports and
probes: detected, then partial, then no match (something answered), then
transport (something refused), then timeout. One open, matching port makes
a sweep exit `0` however many ports were closed.

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
| `internal` | `context_canceled`, `internal_unexpected` |

Per-probe failures (a refused port, a timeout) are not fatal: they are part
of the result, in the text output and in the JSON `results[].error`, and the
exit code reflects them as above.
