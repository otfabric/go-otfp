# Fingerprints

How each protocol is detected and identified, the confidence model shared by
the built-in fingerprinters, and the standards and wire bytes behind them.

## Confidence

Every result carries a [`core.Confidence`](API.md#confidence) in `[0.0, 1.0]`.
Confidence is the **strongest single piece of evidence**, not a sum: two weak
hints never add up to a strong match. The built-in fingerprinters use a
shared scale:

| Value | Constant | Meaning |
|---|---|---|
| 1.00 | `ConfidenceCertain` | a response no other protocol produces, cross-checked (echoed identifiers, CRCs, decoded identity) |
| 0.90 | `ConfidenceHigh` | the protocol's framing and handshake, fully valid |
| 0.60 | `ConfidenceMedium` | valid framing, but one expected check could not be made |
| 0.30 | `ConfidenceLow` | a hint: the shape matches, nothing cross-checked |

A result is reported as **matched** when its confidence reaches
`MatchThreshold` (0.50). Below it the result is a *hint*: `Matched` is false,
and `Confidence` records how close the endpoint came. The engine's early stop
fires at `ConfidenceHigh` by default.

Each result also carries the list of checks that passed (`Evidence`) and a
stable `Fingerprint` signature for inventories and SIEMs.

## Detection vs. identification

- **Detect** (`ModeDetect`) sends the minimal exchange that tells whether the
  endpoint speaks the protocol — a handshake or one harmless request.
- **Identify** (`ModeIdentify`) additionally sends the protocol's standard
  read-only identity request and fills `Result.Identity`. It never writes,
  controls, or changes configuration.

Intrusiveness grades what a fingerprinter puts on the wire so careful scans
can exclude the noisier ones:

- **Passive** — a standard connection handshake or discovery request only.
- **ReadOnly** — also reads application data (SunSpec's holding-register
  marker). Skipped unless the scan allows read-only probes. A passive
  fingerprinter may still take an optional read-only step only when the scan
  allows it: Modbus's FC 03 fallback, OpenADR's 2.0b registration POST.

## Per-protocol

### Modbus TCP (`modbus`, TCP, passive)

Sends Read Device Identification (function 43 / MEI 14, basic stream) to
unit 1. A reply that echoes the probe's transaction identifier, has protocol
identifier 0, a consistent MBAP length, and the function code or its standard
exception (`FC|0x80`, codes 0x01–0x0B) is **certain** Modbus — even "illegal
function" means a Modbus stack parsed the request. Stacks that close the
connection on an unsupported function (digitalpetri, NModbus) are retried, on
a new connection, with a read of one holding register when read-only probes
are allowed. Identify follows the regular identification category across the
pages the device announces. False positives are guarded by the
transaction-ID echo and the protocol-ID/length consistency.

### SunSpec (`sunspec`, TCP, read-only, refines Modbus)

Reads two registers at the SunSpec base addresses 40000, 0 and 50000 (and
their off-by-one variants) looking for the `SunS` marker (0x5375 0x6E53),
retrying with input registers for devices that map the model there. SunSpec
*refines* Modbus: it probes application registers, so the engine runs it only
when read-only probes are allowed and prefers it over a bare Modbus match.
Identify decodes common model 1 (manufacturer, model, options, version,
serial) and walks the model chain.

### IEC 61850 MMS (`mms`, TCP, passive)

A COTP connection confirm alone is **not** MMS — S7 and every other
ISO-on-TCP stack confirm too — so detection completes an association: TPKT +
COTP CR (transport selector 0x0001), then an ISO 8327 session CONNECT, an ISO
8823 presentation CP, an ACSE AARQ for the MMS application context
(1.0.9506.2.3) and an MMS Initiate-Request. An Initiate-Response is
**certain**; an ACSE/MMS-level rejection is still **high** (an MMS stack).
Identify calls the MMS Identify service (vendor, model, revision) and
concludes the association. The probe bytes match those the `go-mms` client
sends.

### Siemens S7comm / S7comm-plus (`s7comm`, TCP, passive)

Opens COTP with the programming-device calling TSAP 0x0100 and a called TSAP
for rack 0, slots 2/1/3 in turn, then sends S7 Setup Communication. An
Ack-Data with the S7 protocol identifier 0x32 is **certain** S7comm and gives
the negotiated PDU size; a 0x72 protocol identifier is **S7comm-plus**
(S7-1200/1500). Identify reads the system status lists 0x0011 (module
identification: order number, hardware/firmware version) and 0x001C
(component identification: module and plant names, serial) and infers the CPU
family from the order number.

### OPC UA (`opcua`, TCP, passive)

Performs the UACP hello handshake: a HEL carrying the endpoint URL
`opc.tcp://host:port`. An ACK is **certain**; an ERR (for example
`BadTcpEndpointUrlInvalid` when the URL does not match the server's endpoint)
is also certain — no other protocol frames a `HELF`/`ACKF`/`ERRF` message.
Identify opens an anonymous secure channel with security policy None and
calls GetEndpoints, returning the application name, URIs and security
policies. The validity of `MessageSize` and the `F` chunk type guard against
four-ASCII-byte false positives.

### EtherNet/IP (`enip`, TCP and UDP, passive)

Sends ListIdentity (command 0x0063), which needs no session and which every
EtherNet/IP target answers with its CIP Identity object. Over UDP it is a
single datagram; over TCP the encapsulation header is validated. The command
echo, a success status and the echoed sender context make a match **certain**
and yield vendor (named from the ODVA list), device type, product code,
revision, serial and product name. The ODVA vendor and device-type tables are
generated from `go-ethernetip` (see `internal/cmd/gencip`).

### BACnet/IP (`bacnet`, UDP, passive)

Sends a confirmed ReadProperty for the Object_Identifier of the wildcard
device object (instance 4194303), which a device answers with a unicast
ComplexACK carrying its real device object identifier — an answer that
reaches a probing socket directly, unlike the broadcast I-Am that Who-Is
draws (a Who-Is is the fallback). Any ComplexACK, Error, Reject, Abort, I-Am
or BVLC-Result identifies BACnet; a valid NPDU version and a parsable APDU
type guard against weak `0x81`-prefix matches. Identify reads the device
object's name, vendor name and identifier, model name, firmware revision and
application software version.

### PROFINET IO (`profinet`, UDP, passive)

PROFINET's acyclic services run over connectionless DCE/RPC version 4 on UDP
34964. Detection sends a ReadImplicit (opnum 5) for the I&M0 record to the
PNIO device interface. A DCE/RPC v4 reply that echoes the request's activity
UUID — response, fault, reject or nocall — identifies PROFINET, because the
activity UUID cannot be guessed. Identify decodes the I&M0 record (vendor ID,
order ID, serial, hardware and software revisions). DCP Identify runs over
raw Layer-2 Ethernet and needs privileges, so it is out of scope here.

> The previous version of this library probed BACnet and PROFINET over TCP.
> Both are wrong: BACnet/IP is UDP 47808, and PROFINET CM is connectionless
> DCE/RPC **v4** over UDP 34964. The current fingerprinters probe the correct
> transports.

### DNP3 (`dnp3`, TCP, passive)

Sends data-link REQUEST_LINK_STATUS frames — no application layer, answered
in any state — first to the self address 0xFFFC, then, in the same write, to
the configured candidate outstation addresses (10, 1, 1024, 0, 3, 4). A
LINK_STATUS reply with the 0x0564 start octets, a valid header CRC and the
secondary direction is **certain** and reveals the outstation and master
addresses. Broadcast destinations are never used (outstations do not answer
them). Identify reads the device attributes (group 0, variation 254).

### IEC 60870-5-104 (`iec104`, TCP, passive)

Sends TESTFR act, which a controlled station answers with TESTFR con in any
state without starting data transfer. The reply must be the confirmation
(0x83), not an echo of the activation (0x43), so echo services do not match.
Identify starts data transfer (STARTDT), records the spontaneous ASDUs the
station sends — the common address, and type identifiers such as an end of
initialisation — acknowledges them and stops data transfer again. No
interrogation or command is sent.

### OCPP (`ocpp`, TCP/WebSocket, passive)

Opens a WebSocket upgrade to a charger path, offering the subprotocols
`ocpp2.1`, `ocpp2.0.1` and `ocpp1.6`. A 101 that echoes one of them is
**certain** OCPP and gives the negotiated version; a 401 with the OCPP Basic
realm is **high**. The connection is closed without a BootNotification. Run
over a TLS target for a `wss://` CSMS.

### IEEE 2030.5 (`ieee2030.5`, TCP/TLS, passive)

IEEE 2030.5 mandates mutual TLS with ECDSA certificates and the cipher suite
`TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8`. Without a device certificate the data
model cannot be read, so detection examines the TLS layer: a server that
requests a client certificate and presents an ECDSA certificate is the shape
of a 2030.5 server (**high**); a server that offers only CCM_8 (which the Go
standard library lacks) aborts the handshake in a recognisable way (**high**).
When the handshake can be completed (an anonymous or misconfigured server),
GET /dcap and the `urn:ieee:std:2030.5:ns` DeviceCapability document are
**certain**.

### OpenADR (`openadr`, TCP, passive)

OpenADR 3 is a REST/JSON API: GET /auth/server returns the VTN's OAuth2
tokenURL (**certain**); GET /programs returns 401 Bearer with a JSON problem
body, or a 200 JSON array for an anonymous VTN (**high**). OpenADR 2.0b is
detected by posting an `oadrQueryRegistration` to the 2.0b registration
endpoint and recognising the `oadrCreatedPartyRegistration` response and the
OpenADR XML namespace (the 2.0b POST is the one read-only step). Run over a
TLS target for an `https://` VTN.

### CAN over TCP (`can`, TCP, passive)

Targets SLCAN (Lawicel) ASCII gateways that expose a CAN bus over a TCP
socket. Sends the version command (`V\r`) and, when needed, the serial
command (`N\r`), and accepts only a strict SLCAN reply: the command's echo
letter, a fixed-width hexadecimal field and a carriage return. ASCII banners
of HTTP, SSH, SMTP and line protocols are rejected, and bare acknowledgements
alone are too weak to confirm. Identify records the firmware version and
serial number.

## Validation

Every fingerprinter's probe bytes and decoders were checked against the
otfabric reference implementations — the `go-<protocol>` libraries' in-process
servers and the published `*-interop` container images — and the
`interop/` suite re-checks detection against the pinned reference servers on
demand. See [INTEROPERABILITY.md](INTEROPERABILITY.md).
