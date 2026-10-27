# otprobe — command-line reference

`otprobe` wraps the go-otfp library for the shell. Every example on this page
is real output, captured from `otprobe` running against the reference
servers of the otfabric `*-interop` suites (the same pinned images the
[interop tests](../INTEROPERABILITY.md) use), published on their well-known
ports on 127.0.0.1.

- [Commands](#commands)
- [Detecting one endpoint](#detecting-one-endpoint) — every protocol, with `--identify`
- [Sweeping a host](#sweeping-a-host)
- [Output formats](#output-formats) — text (default), table, JSON
- [Tracing](#tracing)
- [Errors and exit codes](#errors-and-exit-codes)
- [Shell completion](#shell-completion)
- [Flags](#flags)

## Commands

| Command | Purpose |
|---|---|
| `otprobe detect <target>` | Detect the protocol of one endpoint, or sweep a host's well-known ports |
| `otprobe list` | The supported protocols, their transports, ports and probes |
| `otprobe version` | Version, commit, build date, Go version and platform |
| `otprobe completion bash\|zsh\|fish\|powershell` | The shell completion script |

A target is `host:port`, `[v6]:port`, or `tcp://`, `udp://`, `tls://` followed
by `host:port`. A bare host sweeps the well-known ports.

## Detecting one endpoint

Detection sends each protocol's standard handshake or one harmless request;
`--identify` adds the protocol's own read-only identity service. A port is
tried with every protocol of its transport, that port's own protocols first,
and the scan stops at the first confident match.

### Modbus TCP — Read Device Identification

```console
$ otprobe detect 127.0.0.1:502 --identify
Target:   tcp://127.0.0.1:502
Detected: Modbus TCP, confidence 1.00

  Modbus TCP  1.00  Modbus TCP
    - MBAP header valid (protocol 0, length consistent)
    - transaction ID echoed, normal response to FC 0x2b
    - device identification: 7 objects
    vendor               otfabric
    product              modbus-interop baseline device
    model                baseline
    version              1.0
    productCode          MBI-BASELINE
    userApplicationName  interop
    vendorUrl            https://github.com/otfabric/modbus-interop
    fingerprint          modbus.fc43:fc=0x2b;resp=normal;unit=1;conf=0x82

  2 probes in 15ms
$ echo $?
0
```

### Siemens S7comm

```console
$ otprobe detect 127.0.0.1:102
Target:   tcp://127.0.0.1:102
Detected: Siemens S7comm, confidence 1.00

  Siemens S7comm  1.00  Siemens S7comm
    - COTP connection confirmed for TSAP 0x0102
    - S7 Setup Communication acknowledged, PDU 480
    fingerprint  s7comm.setup:tsap=0x0102;pdu=480;amq=1/1

  2 probes in 4ms
$ echo $?
0
```

The Snap7 reference server does not implement SZL reads, so `--identify`
adds nothing here; against a real CPU it reports the order number, firmware,
module and plant names and serial number.

### EtherNet/IP — ListIdentity over TCP and UDP

```console
$ otprobe detect 127.0.0.1:44818 --identify
Target:   tcp://127.0.0.1:44818
Detected: EtherNet/IP, confidence 1.00

  EtherNet/IP  1.00  EtherNet/IP device
    - ListIdentity: Rockwell Automation/Allen-Bradley, product "OpENer PC"
    - session registered (handle 0x00000001)
    vendor       Rockwell Automation/Allen-Bradley
    vendor id    1
    product      OpENer PC
    version      2.3
    serial       0x075BCD15
    deviceType   Communications Adapter
    productCode  65001
    fingerprint  enip.listidentity:vendor=1;devtype=0x0c;product=65001;rev=2.3;session=ok

  1 probe in 1ms
$ echo $?
0
```

```console
$ otprobe detect udp://127.0.0.1:44818
Target:   udp://127.0.0.1:44818
Detected: EtherNet/IP, confidence 1.00

  EtherNet/IP  1.00  EtherNet/IP device
    - ListIdentity: Rockwell Automation/Allen-Bradley, product "OpENer PC"
    vendor       Rockwell Automation/Allen-Bradley
    vendor id    1
    product      OpENer PC
    version      2.3
    serial       0x075BCD15
    deviceType   Communications Adapter
    productCode  65001
    fingerprint  enip.listidentity:vendor=1;devtype=0x0c;product=65001;rev=2.3

  1 probe in 1ms
$ echo $?
0
```

### BACnet/IP — the Device object

```console
$ otprobe detect udp://127.0.0.1:47808 --identify
Target:   udp://127.0.0.1:47808
Detected: BACnet/IP, confidence 1.00

  BACnet/IP  1.00  BACnet/IP device
    - ReadProperty ComplexACK from the device object
    - device identity properties read
    vendor                      BACnet Stack at SourceForge
    vendor id                   260
    model                       GNU
    version                     1.6.1
    name                        InteropDevice
    applicationSoftwareVersion  1.0
    deviceInstance              1234
    fingerprint                 bacnet.readproperty:apdu=complex-ack

  1 probe in 4ms
$ echo $?
0
```

### OPC UA — GetEndpoints

```console
$ otprobe detect 127.0.0.1:4840 --identify
Target:   tcp://127.0.0.1:4840
Detected: OPC UA (opc.tcp), confidence 1.00

  OPC UA / opc.tcp  1.00  OPC UA server
    - UACP hello acknowledged
    - secure channel opened (policy None)
    - GetEndpoints: 1 endpoint(s)
    name              OTFabric OPC UA Compatibility Server
    applicationUri    urn:otfabric:opcua-interop:server
    productUri        urn:otfabric:opcua-interop
    securityPolicies  None
    fingerprint       opcua.hel:ack=1;recvbuf=65535;sendbuf=65535;policies=None

  1 probe in 2ms
$ echo $?
0
```

### DNP3 — link status

```console
$ otprobe detect 127.0.0.1:20000
Target:   tcp://127.0.0.1:20000
Detected: DNP3, confidence 1.00

  DNP3  1.00  DNP3 outstation 1024
    - valid DNP3 frame, but not a secondary reply
    - LINK_STATUS from outstation 1024 to master 1, header CRC valid
    outstationAddress  1024
    fingerprint        dnp3.link:ctrl=0x0b;dfc=false

  1 probe in 1ms
$ echo $?
0
```

### IEC 60870-5-104

```console
$ otprobe detect 127.0.0.1:2404 --identify
Target:   tcp://127.0.0.1:2404
Detected: IEC 60870-5-104, confidence 1.00

  IEC 60870-5-104  1.00  IEC 60870-5-104 controlled station
    - TESTFR con answers TESTFR act
    - STARTDT con
    fingerprint  iec104.apci:testfr=con;startdt=con

  1 probe in 1.019s
$ echo $?
0
```

### OCPP — WebSocket subprotocol

A CSMS refuses chargers it does not know, so give a station identity it
accepts with `--path` (without it, the probe uses a random identity and a
strict CSMS answers 404, a weak hint only):

```console
$ otprobe detect 127.0.0.1:9000 --path /ocpp/OT-FABRIC-TEST-001
Target:   tcp://127.0.0.1:9000
Detected: OCPP (OCPP 2.0.1), confidence 1.00

  OCPP / OCPP 2.0.1  1.00  OCPP CSMS
    - WebSocket upgrade accepted with OCPP subprotocol ocpp2.0.1
    ocppVersion  2.0.1
    fingerprint  ocpp.ws:subprotocol=ocpp2.0.1

  1 probe in 2ms
$ echo $?
0
```

### OpenADR 3

```console
$ otprobe detect 127.0.0.1:8080 --safe
Target:   tcp://127.0.0.1:8080
Detected: OpenADR (OpenADR 3), confidence 1.00

  OpenADR / OpenADR 3  1.00  OpenADR 3 VTN
    - GET /auth/server returned an OpenADR 3 tokenURL
    tokenUrl     http://127.0.0.1:8080/auth/token
    fingerprint  openadr.v3:auth=server

  2 probes in 253ms
$ echo $?
0
```

## Sweeping a host

Without a port, `otprobe` sweeps the well-known ports of the selected
protocols (`--ports` gives an explicit list) and tries, on each port, only
the protocols registered for it. Closed ports are summarised at the end.
`--safe` keeps to passive probes and paces them 250 ms apart:

```console
$ otprobe detect 127.0.0.1 --safe
Target:   tcp://127.0.0.1:102
Detected: Siemens S7comm, confidence 1.00

  Siemens S7comm  1.00  Siemens S7comm
    - COTP connection confirmed for TSAP 0x0102
    - S7 Setup Communication acknowledged, PDU 480
    fingerprint  s7comm.setup:tsap=0x0102;pdu=480;amq=1/1

  2 probes in 258ms

Target:   tcp://127.0.0.1:502
Detected: Modbus TCP, confidence 1.00

  Modbus TCP  1.00  Modbus TCP
    - MBAP header valid (protocol 0, length consistent)
    - transaction ID echoed, normal response to FC 0x2b
    - device identification: 3 objects
    vendor       otfabric
    product      MBI-BASELINE
    version      1.0
    fingerprint  modbus.fc43:fc=0x2b;resp=normal;unit=1;conf=0x82

  1 probe in 3ms

Target:   tcp://127.0.0.1:2404
Detected: IEC 60870-5-104, confidence 1.00

  IEC 60870-5-104  1.00  IEC 60870-5-104 controlled station
    - TESTFR con answers TESTFR act
    fingerprint  iec104.apci:testfr=con

  1 probe in 5ms

Target:   tcp://127.0.0.1:4840
Detected: OPC UA (opc.tcp), confidence 1.00

  OPC UA / opc.tcp  1.00  OPC UA server
    - UACP hello acknowledged
    fingerprint  opcua.hel:ack=1;recvbuf=65535;sendbuf=65535

  1 probe in 2ms

Target:   tcp://127.0.0.1:8080
Detected: OpenADR (OpenADR 3), confidence 1.00

  OpenADR / OpenADR 3  1.00  OpenADR 3 VTN
    - GET /auth/server returned an OpenADR 3 tokenURL
    tokenUrl     http://127.0.0.1:8080/auth/token
    fingerprint  openadr.v3:auth=server

  2 probes in 259ms

Target:   tcp://127.0.0.1:9000
Detected: none (no protocol matched)

  1 probe in 2ms

Target:   tcp://127.0.0.1:20000
Detected: DNP3, confidence 1.00

  DNP3  1.00  DNP3 outstation 1024
    - valid DNP3 frame, but not a secondary reply
    - LINK_STATUS from outstation 1024 to master 1, header CRC valid
    outstationAddress  1024
    fingerprint        dnp3.link:ctrl=0x0b;dfc=false

  1 probe in 1ms

Target:   tcp://127.0.0.1:44818
Detected: EtherNet/IP, confidence 1.00

  EtherNet/IP  1.00  EtherNet/IP device
    - ListIdentity: Rockwell Automation/Allen-Bradley, product "OpENer PC"
    vendor       Rockwell Automation/Allen-Bradley
    vendor id    1
    product      OpENer PC
    version      2.3
    serial       0x075BCD15
    deviceType   Communications Adapter
    productCode  65001
    fingerprint  enip.listidentity:vendor=1;devtype=0x0c;product=65001;rev=2.3

  1 probe in 1ms

Closed:   80, 443, 802, 1502, 2000, 2222, 3000, 3782, 4443, 4843, 5020, 8443, 8444, 8445, 8887, 19228, 19998, 19999, 29536, 48010, 62541
$ echo $?
0
```

Port 9000 answered but matched nothing: it is the OCPP CSMS, which refuses
the random charger identity of a sweep; probe it with `--path` as shown
above.

## Output formats

Text is the default, for people. `--format table` (`-o table`) prints one row
per probe — here with `--all`, which runs every probe instead of stopping at
the first match, on the S7 server:

```console
$ otprobe detect 127.0.0.1:102 --format table --all -t 500ms
TARGET               PROTOCOL    MATCH  CONF  VARIANT  DETAILS
tcp://127.0.0.1:102  s7comm      yes    1.00  -        Siemens S7comm
tcp://127.0.0.1:102  mms         hint   0.30  -        ISO-on-TCP without MMS
tcp://127.0.0.1:102  iec104      error  0.00  -        iec104 read 127.0.0.1:102: timeout: read tcp 127.0.0.1:60183->127.0.0.1:102: i/o timeout
tcp://127.0.0.1:102  dnp3        error  0.00  -        dnp3 read 127.0.0.1:102: timeout: read tcp 127.0.0.1:60184->127.0.0.1:102: i/o timeout
tcp://127.0.0.1:102  opcua       error  0.00  -        opcua read 127.0.0.1:102: timeout: read tcp 127.0.0.1:60185->127.0.0.1:102: i/o timeout
tcp://127.0.0.1:102  modbus      error  0.00  -        modbus read 127.0.0.1:102: timeout: read tcp 127.0.0.1:60187->127.0.0.1:102: i/o timeout
tcp://127.0.0.1:102  sunspec     error  0.00  -        sunspec read 127.0.0.1:102: timeout: read tcp 127.0.0.1:60188->127.0.0.1:102: i/o timeout
tcp://127.0.0.1:102  enip        error  0.00  -        enip read 127.0.0.1:102: timeout: read tcp 127.0.0.1:60189->127.0.0.1:102: i/o timeout
tcp://127.0.0.1:102  ocpp        error  0.00  -        ocpp read 127.0.0.1:102: timeout: read tcp 127.0.0.1:60190->127.0.0.1:102: i/o timeout
tcp://127.0.0.1:102  ieee2030.5  no     0.00  -        not IEEE 2030.5
tcp://127.0.0.1:102  openadr     no     0.00  -        not OpenADR
tcp://127.0.0.1:102  can         error  0.00  -        can read 127.0.0.1:102: timeout: read tcp 127.0.0.1:60195->127.0.0.1:102: i/o timeout
$ echo $?
0
```

`--format json` is a secondary, machine-readable format with a versioned
schema, documented in [json-output.md](json-output.md):

```console
$ otprobe detect 127.0.0.1:44818 --protocol enip --identify --format json
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
      "detected": {
        "protocol": "enip",
        "name": "EtherNet/IP",
        "matched": true,
        "confidence": 1,
        "details": "EtherNet/IP device",
        "evidence": [
          "ListIdentity: Rockwell Automation/Allen-Bradley, product \"OpENer PC\"",
          "session registered (handle 0x00000001)"
        ],
        "identity": {
          "vendor": "Rockwell Automation/Allen-Bradley",
          "vendorId": "1",
          "product": "OpENer PC",
          "version": "2.3",
          "serial": "0x075BCD15",
          "attributes": {
            "deviceType": "Communications Adapter",
            "productCode": "65001"
          }
        },
        "fingerprint": {
          "id": "enip.listidentity",
          "signature": "vendor=1;devtype=0x0c;product=65001;rev=2.3;session=ok",
          "metadata": {
            "deviceType": "12",
            "vendorId": "1"
          }
        },
        "durationMs": 2
      },
      "results": [
        {
          "protocol": "enip",
          "name": "EtherNet/IP",
          "matched": true,
          "confidence": 1,
          "details": "EtherNet/IP device",
          "evidence": [
            "ListIdentity: Rockwell Automation/Allen-Bradley, product \"OpENer PC\"",
            "session registered (handle 0x00000001)"
          ],
          "identity": {
            "vendor": "Rockwell Automation/Allen-Bradley",
            "vendorId": "1",
            "product": "OpENer PC",
            "version": "2.3",
            "serial": "0x075BCD15",
…
```

`list` and `version` take `--format` as well; `OTPROBE_OUTPUT_FORMAT` sets
the default of every command:

```console
$ otprobe version --format json
{
  "buildDate": "20261027-02:01:33",
  "commit": "de6de49",
  "go": "go1.27.3",
  "platform": "darwin/arm64",
  "version": "v0.0.3-16-gde6de49-dirty"
}
$ echo $?
0
```

## Tracing

`--trace` prints every probe and response in hex (and adds `exchanges` to
the JSON):

```console
$ otprobe detect 127.0.0.1:2404 --protocol iec104 --trace
Target:   tcp://127.0.0.1:2404
Detected: IEC 60870-5-104, confidence 1.00

  IEC 60870-5-104  1.00  IEC 60870-5-104 controlled station
    - TESTFR con answers TESTFR act
    fingerprint  iec104.apci:testfr=con

  1 probe in 5ms

  trace iec104
    testfr
      > 680443000000
      < 680483000000
$ echo $?
0
```

`--debug` logs each probe and its outcome to stderr as it runs.

## Errors and exit codes

The exit code says what happened; it is stable for scripts. Full table:
[exitcodes.md](exitcodes.md).

| Code | Meaning |
|---|---|
| 0 | a protocol was detected at high confidence |
| 1 | the target answered, but no protocol matched |
| 2 | usage: unknown command or flag, wrong number of arguments |
| 3 | invalid input: a target, protocol, format or flag combination that does not make sense; nothing was sent |
| 4 | the target could not be reached: refused, unreachable, TLS failure |
| 5 | nothing answered in time |
| 7 | a protocol matched, but below the high-confidence threshold |
| 10 | interrupted, output could not be written, or an internal error |

```console
$ otprobe detect 127.0.0.1:8080 --protocol modbus,s7comm
Target:   tcp://127.0.0.1:8080
Detected: none (no protocol matched)

  2 probes in 3ms
$ echo $?
1
```

```console
$ otprobe detect 127.0.0.1:9 --protocol modbus
Target:   tcp://127.0.0.1:9
Detected: none (connection refused)

  1 probe in 0s
$ echo $?
4
```

```console
$ otprobe detect 127.0.0.1:47808 --network udp --protocol enip -t 1s
Target:   udp://127.0.0.1:47808
Detected: none (no answer)

  1 probe in 1.002s
$ echo $?
5
```

```console
$ otprobe detect 127.0.0.1:502 --protocol modbuz
error: unknown protocol "modbuz" (see otprobe list)
$ echo $?
3
```

```console
$ otprobe detect 127.0.0.1:502 --frobnicate
error: unknown flag: --frobnicate
$ echo $?
2
```

With `--format json`, a fatal error is a single JSON object on stdout, and
nothing is written to stderr:

```console
$ otprobe detect 127.0.0.1:502 --protocol modbuz --format json
{
  "error": {
    "code": "invalid_protocol",
    "kind": "invalid_input",
    "message": "unknown protocol \"modbuz\" (see otprobe list)"
  }
}
$ echo $?
3
```

## Shell completion

`otprobe completion <shell>` prints a completion script that completes
commands, flags and flag values: protocol names for `--protocol` and
`--exclude` (comma lists too), formats, networks, well-known ports for
`--ports`, and target schemes.

```console
$ source <(otprobe completion bash)                              # bash, this shell
$ otprobe completion bash > /etc/bash_completion.d/otprobe       # bash, permanently
$ otprobe completion zsh > "${fpath[1]}/_otprobe"                # zsh
$ otprobe completion fish > ~/.config/fish/completions/otprobe.fish
$ otprobe completion powershell | Out-String | Invoke-Expression
```

What the shell receives (cobra's completion protocol):

```console
$ otprobe __complete detect 10.0.0.5:502 --protocol mo
modbus	Modbus TCP
mms	IEC 61850 MMS
s7comm	Siemens S7comm
opcua	OPC UA
bacnet	BACnet/IP
can	CAN (TCP gateway)
profinet	PROFINET
dnp3	DNP3
iec104	IEC 60870-5-104
enip	EtherNet/IP
sunspec	SunSpec Modbus
ocpp	OCPP
ieee2030.5	IEEE 2030.5
openadr	OpenADR
:6
```

```console
$ otprobe __complete detect 10.0.0.5:502 --format 
text
json
table
:4
```

## Flags

Run `otprobe detect --help` for the full list:

| Flag | Meaning |
|---|---|
| `-p, --port` | the port (overrides one in the target) |
| `--ports` | sweep these ports of a bare host |
| `--network` | `tcp` or `udp` (default: from the scheme) |
| `--tls` | probe over TLS (certificates are not verified) |
| `-t, --timeout` | per-operation timeout (default 3s) |
| `--deadline` | deadline for the whole scan |
| `--protocol`, `--exclude` | select or skip protocols (`otprobe list`) |
| `-i, --identify` | read the device identity |
| `--safe` | passive probes, likely protocols only, 250 ms pacing |
| `--parallel`, `--max-concurrency` | concurrent probes (off by default) |
| `--min-interval` | delay between probes |
| `--all` | run every probe, no early stop |
| `--path` | HTTP/WebSocket path (OCPP station id) |
| `-o, --format` | `text` (default), `table`, `json` |
| `--trace` | raw probe and response bytes |
| `--debug` | log each probe to stderr |
