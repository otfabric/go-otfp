// SPDX-License-Identifier: MIT

package core

import (
	"fmt"
	"strings"
)

// Protocol identifies an OT protocol. The numeric values are stable across
// versions: new protocols are appended, existing ones are never renumbered.
type Protocol uint8

// Known protocols.
const (
	ProtocolUnknown    Protocol = 0
	ProtocolModbus     Protocol = 1
	ProtocolMMS        Protocol = 2
	ProtocolS7         Protocol = 3
	ProtocolOPCUA      Protocol = 4
	ProtocolBACnet     Protocol = 5
	ProtocolCAN        Protocol = 6
	ProtocolPROFINET   Protocol = 7
	ProtocolDNP3       Protocol = 8
	ProtocolIEC104     Protocol = 9
	ProtocolENIP       Protocol = 10
	ProtocolSunSpec    Protocol = 11
	ProtocolOCPP       Protocol = 12
	ProtocolIEEE2030_5 Protocol = 13 //nolint:revive // the standard's name
	ProtocolOpenADR    Protocol = 14
	protocolCount      Protocol = 15 // unexported sentinel
)

type protocolInfo struct {
	slug string // stable machine identifier (CLI, JSON)
	name string // human-readable name
}

var protocolTable = [protocolCount]protocolInfo{
	ProtocolUnknown:    {"unknown", "Unknown"},
	ProtocolModbus:     {"modbus", "Modbus TCP"},
	ProtocolMMS:        {"mms", "IEC 61850 MMS"},
	ProtocolS7:         {"s7comm", "Siemens S7comm"},
	ProtocolOPCUA:      {"opcua", "OPC UA"},
	ProtocolBACnet:     {"bacnet", "BACnet/IP"},
	ProtocolCAN:        {"can", "CAN (TCP gateway)"},
	ProtocolPROFINET:   {"profinet", "PROFINET"},
	ProtocolDNP3:       {"dnp3", "DNP3"},
	ProtocolIEC104:     {"iec104", "IEC 60870-5-104"},
	ProtocolENIP:       {"enip", "EtherNet/IP"},
	ProtocolSunSpec:    {"sunspec", "SunSpec Modbus"},
	ProtocolOCPP:       {"ocpp", "OCPP"},
	ProtocolIEEE2030_5: {"ieee2030.5", "IEEE 2030.5"},
	ProtocolOpenADR:    {"openadr", "OpenADR"},
}

// String returns the human-readable protocol name, e.g. "Modbus TCP".
func (p Protocol) String() string {
	if p < protocolCount {
		return protocolTable[p].name
	}
	return protocolTable[ProtocolUnknown].name
}

// Slug returns the stable machine identifier, e.g. "modbus". Slugs are used
// on the command line and in JSON.
func (p Protocol) Slug() string {
	if p < protocolCount {
		return protocolTable[p].slug
	}
	return protocolTable[ProtocolUnknown].slug
}

// IsValid reports whether p is a known protocol other than ProtocolUnknown.
func (p Protocol) IsValid() bool {
	return p > ProtocolUnknown && p < protocolCount
}

// MarshalText encodes the protocol as its slug.
func (p Protocol) MarshalText() ([]byte, error) {
	return []byte(p.Slug()), nil
}

// UnmarshalText decodes a slug or a name, as [ParseProtocol] does.
func (p *Protocol) UnmarshalText(b []byte) error {
	v, err := ParseProtocol(string(b))
	if err != nil {
		return err
	}
	*p = v
	return nil
}

// ParseProtocol returns the protocol with the given slug or name, compared
// case-insensitively: "modbus", "Modbus TCP" and "MODBUS" all return
// [ProtocolModbus]. A few common aliases are accepted as well ("s7",
// "ethernetip", "iec61850", "2030.5", "sep2").
func ParseProtocol(s string) (Protocol, error) {
	k := strings.ToLower(strings.TrimSpace(s))
	for i := ProtocolUnknown + 1; i < protocolCount; i++ {
		if k == protocolTable[i].slug || k == strings.ToLower(protocolTable[i].name) {
			return i, nil
		}
	}
	if p, ok := protocolAliases[k]; ok {
		return p, nil
	}
	return ProtocolUnknown, fmt.Errorf("unknown protocol %q", s)
}

var protocolAliases = map[string]Protocol{
	"modbustcp":      ProtocolModbus,
	"modbus-tcp":     ProtocolModbus,
	"iec61850":       ProtocolMMS,
	"s7":             ProtocolS7,
	"s7comm-plus":    ProtocolS7,
	"ethernetip":     ProtocolENIP,
	"ethernet/ip":    ProtocolENIP,
	"cip":            ProtocolENIP,
	"opc-ua":         ProtocolOPCUA,
	"bacnetip":       ProtocolBACnet,
	"bacnet/ip":      ProtocolBACnet,
	"slcan":          ProtocolCAN,
	"pnio":           ProtocolPROFINET,
	"iec60870-5-104": ProtocolIEC104,
	"104":            ProtocolIEC104,
	"ieee20305":      ProtocolIEEE2030_5,
	"2030.5":         ProtocolIEEE2030_5,
	"sep2":           ProtocolIEEE2030_5,
	"csip":           ProtocolIEEE2030_5,
}

// AllProtocols returns every known protocol other than ProtocolUnknown, in
// numeric order.
func AllProtocols() []Protocol {
	out := make([]Protocol, 0, protocolCount-1)
	for i := ProtocolUnknown + 1; i < protocolCount; i++ {
		out = append(out, i)
	}
	return out
}

// Network is the transport a fingerprinter probes over.
type Network uint8

// Networks.
const (
	// TCP is a TCP stream, optionally wrapped in TLS (see Target.TLS).
	TCP Network = iota
	// UDP is a UDP datagram exchange.
	UDP
)

// String returns "tcp" or "udp".
func (n Network) String() string {
	if n == UDP {
		return "udp"
	}
	return "tcp"
}

// MarshalText encodes the network as "tcp" or "udp".
func (n Network) MarshalText() ([]byte, error) { return []byte(n.String()), nil }

// UnmarshalText decodes "tcp" or "udp".
func (n *Network) UnmarshalText(b []byte) error {
	v, err := ParseNetwork(string(b))
	if err != nil {
		return err
	}
	*n = v
	return nil
}

// ParseNetwork returns the network named "tcp" or "udp" (case-insensitive).
// The empty string is TCP.
func ParseNetwork(s string) (Network, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "tcp":
		return TCP, nil
	case "udp":
		return UDP, nil
	}
	return TCP, fmt.Errorf("unknown network %q (want tcp or udp)", s)
}
