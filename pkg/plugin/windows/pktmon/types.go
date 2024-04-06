package pktmon

import (
	"net"

	"github.com/cilium/cilium/api/v1/flow"
)

type PktMon interface {
	Initialize() error
	GetNextPacket() (*Packet, *Metadata, error)
}

// surely there is a better struct around the repo that is the same as this
type Packet struct {
	SourceIP   net.IP
	DestIP     net.IP
	SourcePort uint32
	DestPort   uint32
	Protocol   uint8
	Direction  string // we currently don't set this, but it is available, check pktmon notes for Direction enum
	syn        uint16
	ack        uint16
	fin        uint16
	rst        uint16
	psh        uint16
	urg        uint16
}

type Metadata struct {
	Timestamp     int64
	DropReason    uint32
	ComponentID   uint32
	PayloadLength uint64
	Verdict       flow.Verdict
	MissedPackets uint32
}
