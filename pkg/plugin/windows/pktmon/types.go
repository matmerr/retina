package pktmon

import (
	"net"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PktMon interface {
	Initialize() error
	GetNextPacket() (*Packet, *Metadata, error)
}

type Packet struct {
	SourceIP   net.IP
	DestIP     net.IP
	SourcePort uint32
	DestPort   uint32
	Protocol   uint8
	Direction  string
	syn        bool
	ack        bool
	fin        bool
	rst        bool
	psh        bool
	urg        bool
	dns        *layers.DNS
}

type MockPktMon struct{}

func (m *MockPktMon) Initialize() error {
	return nil
}

func (m *MockPktMon) GetNextPacket() (gopacket.Packet, *Metadata, error) {
	ip := &layers.IPv4{
		SrcIP: net.IP{1, 2, 3, 4},
		DstIP: net.IP{5, 6, 7, 8},
		// etc...
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{} // See SerializeOptions for more details.
	err := ip.SerializeTo(buf, opts)
	return nil, nil, err
}

type Metadata struct {
	Timestamp     int64
	DropReason    uint32
	ComponentID   uint32
	PayloadLength uint64
	Verdict       flow.Verdict
	MissedPackets uint32
}
