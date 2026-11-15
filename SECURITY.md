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
- A full scan may open several protocols' connections to the same port, one at a time. Some probes open protocol state before the connection is closed, and the device sees a session come and go:

  | Probe | State it opens | How it ends |
  |---|---|---|
  | S7comm | COTP connection, S7 Setup Communication | the TCP connection is closed |
  | MMS | COTP connection and an MMS association (Initiate) | Conclude, then close |
  | OPC UA, identify | an anonymous secure channel with security policy None, for GetEndpoints; no session | the TCP connection is closed (no CloseSecureChannel is sent) |
  | EtherNet/IP over TCP, identify | an encapsulation session (RegisterSession) | the TCP connection is closed (no UnRegisterSession is sent) |
  | OCPP | a completed WebSocket upgrade | the TCP connection is closed, without a BootNotification |
  | MQTT, Sparkplug B | an MQTT session (CONNECT, clean session), with QoS 0 subscriptions for Sparkplug B and for MQTT identify with read-only probes | UNSUBSCRIBE, DISCONNECT |
  | CANopen gateway, identify with read-only probes | SDO uploads on the CAN bus behind the gateway | each upload completes |
  | IEC 60870-5-104, identify with `StartDT` only | data transfer on the probe's connection (STARTDT) | acknowledgement, STOPDT, close |

- **IEC 60870-5-104.** By default, and always under `--safe` (`core.SafeEngineConfig`), the probe sends TESTFR act and nothing else, in detect and in identify mode: the station's data transfer state and event queue are not touched. Starting data transfer is an explicit choice: `iec104.Fingerprinter.StartDT` in the library, `otprobe detect --identify --iec104-startdt`. It changes the station. A station gives data transfer to the connection that started it: with one redundancy group, the connection of a control centre stops receiving, or is closed. What the probe acknowledges leaves the station's event queue and is not sent to the control centre again. Use it on a station no control centre is connected to. The option is refused, with an error and before anything is sent, when the scan allows passive probes only.
- **MQTT and Sparkplug B client identifier.** The probes connect with a random client identifier. `ClientID` replaces it: a broker has one session per identifier, so the identifier of a connected client makes the broker disconnect that client, and the probe's clean session discards the session stored for it.
- Detection is sequential by default (`core.DefaultEngineConfig`, `otprobe detect` without `--parallel`). Use `--safe` (`core.SafeEngineConfig`) for passive probes only, the likely protocols of the port first, and a 250 ms gap between probes; `--max-concurrency` and `--min-interval` tune this further.
- `--proxy socks5://…` sends the probes through a SOCKS5 proxy without credentials; the proxy sees every target and probe. It carries TCP only: UDP targets are refused rather than probed directly. `--source-addr` binds the probes to one local address.
- `--all` runs every applicable probe instead of stopping at the first confident match; omit it (the default) to send the fewest probes.

### Restricting what a scan reaches

An application that lets users scan only approved networks should enforce the allowlist in `EngineConfig.Dialer` (or `Options.Dialer`), for example in a `net.Dialer.Control` hook, which sees the resolved IP right before connecting. Checking the host name before the scan leaves a DNS-rebinding gap. Every connection of the built-in fingerprinters, TCP and UDP, goes through the dialer; a refused dial is the result's `Error`, so the scan reports "could not decide" for that target. The same hook dials through a proxy or binds a source address. With `Parallel` the dialer is called from several goroutines at once.

`Target.Host` and `Target.Path` are sent to the endpoint by the web fingerprinters, in a Host header and in the request line of OCPP's one GET. `Target.Validate`, and so `Engine.Scan`, `Engine.Detect` and `ParseTarget`, accept a host without spaces, control characters and `/`, and a path that starts with `/` and holds no space or control character: what one header value and one request line can carry. The OCPP, OpenADR and IEEE 2030.5 fingerprinters check the same when they are called directly (`ocpp.Config.Path` included) and return an error before they connect. An application that takes the host or the path from its own users can pass them on as they are; it still decides which hosts they may name.

### Results are hints, not proof

The fingerprinted protocols carry no authentication, and the probes run over plain TCP. A result says how a peer answered, not what it is: any host can imitate the expected response. Do not base access decisions on a match.

### What a result holds

Everything in a `Result` that came from the endpoint is data from an untrusted peer.

- **Text.** The variant, the details, every evidence line, the fingerprint and every identity field and attribute hold graphic characters only (`unicode.IsGraphic`): no control character (C0, DEL, C1), no format character (directional marks, zero-width characters), no line or paragraph separator, and valid UTF-8. A string read off the wire is cut to 512 runes, any string of a result to 4096. The built-in fingerprinters produce their results through one builder that applies this (`internal/fpx`), and every `FuzzDetect` target checks it. A fingerprinter of your own is responsible for its own strings.
- **otprobe output.** The text and table formats write every value of a result with the characters that are not graphic as escapes (`\x1b`, `\n`, `\u202e`), also for a fingerprinter outside the library, so a value cannot move the cursor or start an output line. The JSON format is JSON: it escapes what JSON requires and is meant for a parser, not a terminal.
- **Trace.** `Exchanges` holds raw octets and is bounded per connection (table below).

### Input handling

- Each response is read with a deadline (`Target.Timeout`, 3 s by default) into a bounded buffer, and every parser checks lengths before use. A length or count is compared with what remains of the input, not added to an offset first, so the comparison is the same where `int` has 32 bits (`linux/arm`, `linux/386`) and where it has 64.
- The parsers are fuzzed: each protocol package has a `Fuzz` target, as do the shared TPKT/COTP and Modbus MBAP codecs and the HTTP response framer. `make fuzz` runs them, and CI fuzzes briefly on every pull request.
- The tests run on a 32-bit platform every night (`GOARCH=386`, [TESTING.md](TESTING.md)).

### Resource limits

What one probe of one endpoint reads and keeps, whatever the endpoint sends. Each limit is a constant in the package named, and has a test that feeds the limit and one more and asserts the outcome and an allocation budget (`TestLimits` in each package unless another test is named; `internal/fuzzkit.Limits`).

| Fingerprinter | Largest read | Reads per probe | Kept in the result |
|---|---|---|---|
| Modbus (`modbus`) | one ADU of 260 octets | 1 request; identify follows "more follows" for at most 8 Read Device Identification responses of a category (regular, then basic when regular is refused); 1 FC 03 request on a second connection with read-only probes | objects by their one-octet identifier, each at most 255 octets |
| SunSpec (`sunspec`) | one ADU of 260 octets | 2 registers at each of 8 base addresses with FC 03 and 3 with FC 04; identify reads the common model and walks at most 32 models | 32 model identifiers |
| MMS (`mms`) | 8192 octets of one TPKT frame | 4 exchanges (COTP, Initiate, Identify, Conclude); BER search depth 16 | 3 identity strings |
| S7comm (`s7`) | 4096 octets of one TPKT frame | 1 connection per called TSAP (3 by default); Setup Communication and 2 SZL reads on the one that answers | SZL records within the frame |
| OPC UA (`opcua`) | one message of 1 MiB | 3 exchanges (HEL, OpenSecureChannel, GetEndpoints) | 64 endpoint descriptions decoded, 16 security policies listed |
| EtherNet/IP (`enip`) | 65535 octets over TCP, one datagram over UDP | ListIdentity; RegisterSession in identify mode over TCP | one identity item |
| BACnet/IP (`bacnet`) | one datagram of 1500 octets | 2 round trips; 6 property reads in identify mode | 6 identity strings |
| PROFINET (`profinet`) | one datagram of 1500 octets | 1 round trip | one I&M0 block |
| DNP3 (`dnp3`) | one frame of 292 octets | at most 8 frames before the link status; identify at most 32 frames within 3 timeouts | attributes by their one-octet variation, each at most 255 octets |
| IEC 60870-5-104 (`iec104`) | one APDU of 255 octets | at most 4 APDUs before the TESTFR confirmation; with `StartDT`, at most 256 APDUs in a window of at most 1 s (`MaxAPDUs`; `TestListeningWindowIsBounded`) | 16 common addresses and 16 type identifiers, the rest counted (`TestIdentityListsAreBounded`) |
| OCPP (`ocpp`) | 16384 octets of response header, 4096 of body | 1 request | the negotiated subprotocol |
| OpenADR (`openadr`) | 16384 octets of response header, 8192 of body | 3 requests on 3 connections, the third with read-only probes | the token URL |
| IEEE 2030.5 (`ieee2030`) | one TLS record of 64 KiB; 16384 + 8192 octets of the `/dcap` response | a flight of at most 64 records and 256 KiB of handshake messages within 2 timeouts; 1 request on a second connection | the certificate subject, the poll rate |
| CAN gateway (`can`) | one line of 64 octets | 2 commands | version and serial |
| CANopen gateway (`canopen`) | one line of 256 octets | 1 command, and 7 SDO uploads in identify mode with read-only probes; at most 6 lines per command | strings of 64 characters |
| KNXnet/IP (`knx`) | one frame or datagram of 4096 octets | 1 round trip, 2 over UDP | 16 individual addresses |
| MQTT (`mqtt`) | one packet of 64 KiB | at most 2 connections; identify with read-only probes reads at most 32 packets in a window of at most 1 s, and 16 more for the UNSUBACK | 32 CONNACK properties, strings of 128 runes |
| Sparkplug B (`sparkplugb`) | one packet of 256 KiB | at most 2 connections; 256 messages and 8 other packets in a window of at most 2 s | 16 entries per list of identifiers, 32 metric names of 64 runes |

For every fingerprinter:

| Limit | Value | Where | Test |
|---|---|---|---|
| Time of one probe | 64 target timeouts against any sequence of replies; 40 against a silent, dripping, closing or garbage-sending peer | every `FuzzDetect` target (`internal/fuzzkit`), the misbehaving servers of `e2e/robustness_test.go` | the same |
| Datagrams that are not the answer, per UDP round trip | 64, then the round trip ends as when its window ends | `internal/wire` `MaxStrays` | `TestStrayDatagramBound`, `protocols/bacnet` `TestDiscardedDatagramsAreBounded` |
| Trace (`Options.Trace`), per connection | 256 exchanges and 4 MiB of probes and responses, then one entry that counts what was left out | `internal/wire` `MaxExchanges`, `MaxTraceBytes` | `TestTraceExchangeBound`, `TestTraceOctetBound`, `TestTraceRetainsBoundedMemory` |
| Text of a result | 512 runes per string read off the wire, 4096 per string of a result | `internal/fpx` `MaxText`, `MaxLine` | `TestTextBounds`, `TestResultHoldsTextOnly` |

A scan runs the fingerprinters one after the other by default, so the figures of one probe are those of the scan; with `Parallel` they add up across the probes running at once (`MaxConcurrency`).
