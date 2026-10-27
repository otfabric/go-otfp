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
| `protocol` | string | stable slug: `modbus`, `sunspec`, `mms`, `s7comm`, `opcua`, `enip`, `bacnet`, `profinet`, `dnp3`, `iec104`, `ocpp`, `ieee2030.5`, `openadr`, `can` |
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

```json
{"version": "v0.1.0", "commit": "abc1234", "buildDate": "20261027-02:01:42", "go": "go1.23.12", "platform": "linux/amd64"}
```

## Errors

A fatal error replaces the document with one `error` object; see
[exitcodes.md](exitcodes.md).
