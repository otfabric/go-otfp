# JSON output

Text is `otprobe`'s default output; `--format json` (`-o json`) is the
secondary, machine-readable format. The document is versioned by
`schemaVersion`; fields are only added within a version, never renamed or
removed. Durations are integer milliseconds, times RFC 3339 UTC.

## `otprobe detect`

One document per invocation, with one entry in `scans` per scanned port (a
single port gives one; a sweep gives one per port that a selected protocol
uses):

```json
{
  "schemaVersion": 1,
  "scans": [
    {
      "target": "tcp://127.0.0.1:44818",
      "host": "127.0.0.1",
      "port": 44818,
      "network": "tcp",
      "tls": false,
      "startedAt": "2026-10-27T02:01:42.585314Z",
      "durationMs": 2,
      "detected": { "...": "the best result, or null when nothing matched" },
      "results": [ { "...": "one result per probe that ran, best first" } ]
    }
  ]
}
```

A result:

| Field | Type | Meaning |
|---|---|---|
| `protocol` | string | stable slug: `modbus`, `sunspec`, `mms`, `s7comm`, `opcua`, `enip`, `bacnet`, `profinet`, `dnp3`, `iec104`, `ocpp`, `ieee2030.5`, `openadr`, `can`, `knx`, `mqtt`, `sparkplugb`, `canopen` |
| `name` | string | human-readable protocol name |
| `matched` | bool | confidence reached the match threshold (0.50) |
| `confidence` | number | 0.0–1.0 on the shared scale (see FINGERPRINTS.md) |
| `variant` | string? | refinement: `S7comm-plus`, `OCPP 2.0.1`, `OpenADR 3`, … |
| `details` | string? | short explanation |
| `evidence` | string[]? | checks that passed, in order |
| `identity` | object? | with `--identify`: `vendor`, `vendorId`, `product`, `model`, `version`, `serial`, `name`, `attributes` (all optional) |
| `fingerprint` | object? | `id`, `signature` (stable, for inventories) and `metadata` |
| `error` | object? | why the probe could not decide: `kind` (`refused`, `unreachable`, `timeout`, `io`) and `message` |
| `durationMs` | integer | time the probe took |
| `exchanges` | object[]? | with `--trace`: `label`, `probe` and `response` in hex |

A complete example, from the OpENer EtherNet/IP reference adapter, is in
[cli.md](cli.md#output-formats).

## `otprobe list`

```json
{"protocols": [{"protocol": "modbus", "name": "Modbus TCP", "network": "tcp", "ports": [502, 802, 1502, 5020], "intrusiveness": "passive", "probe": "MBAP: Read Device Identification ..."}]}
```

`refines` names the protocol a profile refines (`sunspec` → `modbus`).

## `otprobe version`

`otprobe version --json` (or `--format json`) prints one line, keys in this
order, every key always present:

```json
{"name":"otprobe","version":"0.5.0","tag":"v0.5.0","commit":"1802d0f9afe8642d1e278120b76fcdfac967cb9e","built":"2026-11-07T15:41:49Z","libraries":[],"go":"go1.26.3","platform":"linux/amd64"}
```

| Field | Meaning |
|---|---|
| `name` | `otprobe` |
| `version` | release version without the leading `v`; `dev` for a build without one |
| `tag` | the release tag (`v0.5.0`); `""` for a build that is not a release |
| `commit` | full commit SHA, `-dirty` appended for a modified tree; `unknown` when not known |
| `built` | RFC 3339 UTC build date; `unknown` when not known |
| `libraries` | the OT Fabric `go-*` libraries the binary is built on, other than go-otfp itself: `[{"name":"go-x","version":"1.2.3"}]`, sorted by name; `[]` when none (today) |
| `go` | Go version the binary was built with |
| `platform` | `GOOS/GOARCH` |

This document has no `schemaVersion`; before v0.5.0 it was an indented
object with `version` (with `v`), `commit` (short), `buildDate`, `go` and
`platform`.

## Errors

A fatal error replaces the document with one `error` object; see
[exitcodes.md](exitcodes.md).
