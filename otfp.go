// SPDX-License-Identifier: MIT

// Package otfp fingerprints operational-technology (OT) protocols on a
// network endpoint with safe, connection-level probes.
//
// The library detects which industrial protocol an endpoint speaks —
// Modbus TCP, SunSpec, IEC 61850 MMS, Siemens S7comm, OPC UA, BACnet/IP,
// PROFINET, DNP3, IEC 60870-5-104, EtherNet/IP, OCPP, IEEE 2030.5 and
// OpenADR — by exchanging each protocol's standard handshake or a single
// harmless request, never by writing, controlling or changing a device's
// configuration. In identify mode it additionally issues each protocol's
// read-only identity request (Read Device Identification, the CIP Identity
// object, SZL, MMS Identify, the BACnet Device object, OPC UA GetEndpoints,
// PROFINET I&M0, and the like) and reports vendor, model, version and
// serial where the device provides them.
//
// The engine ([core.Engine]) runs the registered fingerprinters against a
// [core.Target], trying those of the target's well-known port first,
// stopping early on a confident match, and returning a [core.Report]. The
// command otprobe (./cmd/otprobe) wraps the library for the shell.
//
// This module has no dependencies outside the Go standard library and the
// CLI's cobra. The sibling go-<protocol> libraries and the -interop
// container suites are used to validate the fingerprinters, not at runtime.
package otfp

import (
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/protocols/bacnet"
	"github.com/otfabric/go-otfp/protocols/can"
	"github.com/otfabric/go-otfp/protocols/dnp3"
	"github.com/otfabric/go-otfp/protocols/enip"
	"github.com/otfabric/go-otfp/protocols/iec104"
	"github.com/otfabric/go-otfp/protocols/ieee2030"
	"github.com/otfabric/go-otfp/protocols/mms"
	"github.com/otfabric/go-otfp/protocols/modbus"
	"github.com/otfabric/go-otfp/protocols/ocpp"
	"github.com/otfabric/go-otfp/protocols/opcua"
	"github.com/otfabric/go-otfp/protocols/openadr"
	"github.com/otfabric/go-otfp/protocols/profinet"
	"github.com/otfabric/go-otfp/protocols/s7"
	"github.com/otfabric/go-otfp/protocols/sunspec"
)

// Fingerprinters returns a fresh instance of every built-in fingerprinter,
// over both TCP and UDP. EtherNet/IP appears twice, once per transport.
func Fingerprinters() []core.Fingerprinter {
	return []core.Fingerprinter{
		// ISO-on-TCP (port 102): MMS and S7 share the port, so they run
		// first and in that order.
		mms.New(),
		s7.New(),
		// TCP binary protocols.
		modbus.New(),
		sunspec.New(),
		dnp3.New(),
		iec104.New(),
		enip.New(),
		opcua.New(),
		// UDP protocols.
		bacnet.New(),
		profinet.New(),
		enip.NewUDP(),
		// Web-based energy protocols.
		ocpp.New(),
		ieee2030.New(),
		openadr.New(),
		// Niche gateways.
		can.New(),
	}
}

// DefaultRegistry returns a registry pre-loaded with every built-in
// fingerprinter.
func DefaultRegistry() *core.Registry {
	return core.NewRegistry().MustRegister(Fingerprinters()...)
}

// NewEngine returns an engine over DefaultRegistry with the given
// configuration.
func NewEngine(config core.EngineConfig) *core.Engine {
	return core.NewEngine(DefaultRegistry(), config)
}

// DefaultEngine returns an engine over DefaultRegistry with
// [core.DefaultEngineConfig].
func DefaultEngine() *core.Engine {
	return NewEngine(core.DefaultEngineConfig())
}
