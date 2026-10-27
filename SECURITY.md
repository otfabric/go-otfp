# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `go-otfp`, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@otfabric.io**, or open a private advisory on GitHub (the [Security](https://github.com/otfabric/go-otfp/security) tab → **Advisories** → **Report a vulnerability**), with:

- A description of the vulnerability
- Steps to reproduce the issue, ideally a minimal program or test
- The affected version(s)
- Any potential impact you've identified

We will acknowledge your report within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | Best effort |

## Security Considerations

### Probing is active network traffic

`go-otfp` and `otprobe` identify a protocol by sending it a real request and reading the answer. The probes are small and do not write process values, but they are not invisible to the device:

- **Only probe systems you are authorised to scan**, and follow the site's change process for production networks. Probes may raise alerts in OT intrusion detection systems.
- Detection sends a protocol's standard handshake or a single harmless request; it never writes a value, issues a control, or changes a device's configuration. `--identify` adds each protocol's own read-only identity request (Read Device Identification, the CIP Identity object, SZL, MMS Identify, the BACnet Device object, OPC UA GetEndpoints, PROFINET I&M0, …).
- A full scan may open several protocols' connections to the same port, one at a time. Some probes open protocol state before the connection is closed: the S7 probe performs a COTP connect and S7 Setup Communication, the IEC 60870-5-104 probe may send STARTDT in identify mode, and the OCPP probe completes a WebSocket upgrade. Each is closed promptly; the IEC 104 identify probe sends STOPDT before closing.
- Detection is sequential by default (`core.DefaultEngineConfig`, `otprobe detect` without `--parallel`). Use `--safe` (`core.SafeEngineConfig`) for passive probes only, the likely protocols of the port first, and a 250 ms gap between probes; `--max-concurrency` and `--min-interval` tune this further.
- `--all` runs every applicable probe instead of stopping at the first confident match; omit it (the default) to send the fewest probes.

### Results are hints, not proof

The fingerprinted protocols carry no authentication, and the probes run over plain TCP. A result says how a peer answered, not what it is: any host can imitate the expected response. Do not base access decisions on a match.

### Input handling

- Each response is read with a deadline (`Target.Timeout`, 3 s by default) into a bounded buffer, and every parser checks lengths before use.
- The parsers are fuzzed: each protocol package has a `Fuzz` target, as do the shared TPKT/COTP and Modbus MBAP codecs. `make fuzz` runs them, and CI fuzzes briefly on every push.
