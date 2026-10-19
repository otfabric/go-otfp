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

- **Only probe systems you are authorised to scan**, and follow the site's change process for production networks. Probes may raise alerts in OT intrusion detection systems
- Every protocol check opens its own TCP connection; a full `detect` can send up to ten different protocols' requests to the same port
- Some probes open protocol state on the device before the connection is closed: the S7 probe performs a COTP connect and S7 Setup Communication (rack 0, slot 2), the EtherNet/IP probe a RegisterSession, and the IEC 60870-5-104 probe sends STARTDT_ACT. None is followed by a matching teardown message; the TCP connection is simply closed
- The defaults are already sequential (`core.DefaultEngineConfig`, `otprobe detect` without `--parallel`), but with no delay between probes. Use `--safe` (or `core.SafeEngineConfig` with `MinInterval`) to add a 200 ms gap and a concurrency of one, and `--dry-run` to see the plan without sending anything

### Results are hints, not proof

The fingerprinted protocols carry no authentication, and the probes run over plain TCP. A result says how a peer answered, not what it is: any host can imitate the expected response. Do not base access decisions on a match.

### Input handling

- Each response is read with a deadline (`Target.Timeout`, 5 s in `otprobe`) into a fixed buffer of at most 4096 bytes, and every validator checks lengths before use
- The response validators are fuzzed (`FuzzValidateResponse` in each protocol package, plus the shared TPKT/COTP and SLCAN checks)
