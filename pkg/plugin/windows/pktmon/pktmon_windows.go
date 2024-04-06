//go:build experimental

package pktmon

// #cgo CFLAGS: -I c:/some/directory/on/disk/retina/pkg/plugin/windows/pktmon/packetmonitorsupport
// #cgo LDFLAGS: -L c:/some/directory/on/disk/retina/pkg/plugin/windows/pktmon/packetmonitorsupport
// #cgo LDFLAGS: -lpktmonapi -lws2_32
//
// #include "Packetmonitor.h"
// #include "Packetmonitorpacket.h"
// #include "packetmonitorsupportutil.h"
// #include "packetmonitorsupport.h"
// #include "packetmonitorsupport.c"
// #include "packetmonitorpacketparse.c"
import "C"
import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/microsoft/retina/pkg/log"
)

var (
	ErrFailedToStartPktmonPacketCapture error = fmt.Errorf("Failed to start a pktmon packet capture")
	ErrFailedToParseWithGoPacket        error = fmt.Errorf("Failed to parse with gopacket")
	ErrNotSupported                     error = fmt.Errorf("Not supported")
	ErrUnknownPacketType                error = fmt.Errorf("Unknown packet type")

	defaultBufferMultiplier int = 1
)

type WinPktMon struct {
	l *log.ZapLogger
}

func (w *WinPktMon) Initialize() error {
	var UserContext C.PACKETMONITOR_STREAM_EVENT_INFO

	// calling packet capture routine concurrently
	result := C.InitializePacketCapture(unsafe.Pointer(&UserContext), C.int(defaultBufferMultiplier))
	if result != 0 {
		return fmt.Errorf("Pktmon initialize returned code %d, %w", result, ErrFailedToStartPktmonPacketCapture)
	}

	return nil
}

func (w *WinPktMon) GetNextPacket() (*Packet, *Metadata, error) {
	buffer := make([]byte, 9000)
	var bufferSize C.int = 9000
	var payloadLength C.int = 0
	var StreamMetaData C.PACKETMONITOR_STREAM_METADATA_RETINA
	var PacketHeaderInfo C.PACKETMONITOR_PACKET_HEADER_INFO
	var MissedPackets C.int = 0

	// Note: if we pass nil to PacketHeaderInfo, it won't be populated. In the current form, both Go and C are parsing the buffer
	// to create packet struct
	C.GetNextPacket((*C.uchar)(unsafe.Pointer(&buffer[0])), bufferSize, &payloadLength, &StreamMetaData, &PacketHeaderInfo, &MissedPackets)

	packet, err := w.parseWithGoPacket(buffer, StreamMetaData)
	if err != nil {
		if errors.Is(err, ErrFailedToParseWithGoPacket) {
			if PacketHeaderInfo.ParseErrorCode == 0 {
				//w.l.Debug("Packet dropped", zap.Uint32("srcport", uint32(PacketHeaderInfo.PortLocal)), zap.Uint32("dstport", uint32(PacketHeaderInfo.PortRemote)), zap.Uint8("proto", uint8(PacketHeaderInfo.IpProtocol)), zap.Uint32("dropreason", uint32(StreamMetaData.DropReason)))

				packet = &Packet{
					SourcePort: uint32(PacketHeaderInfo.PortLocal),
					DestPort:   uint32(PacketHeaderInfo.PortRemote),
					Protocol:   uint8(PacketHeaderInfo.IpProtocol),
				}
				return nil, nil, fmt.Errorf("Failed to parse with gopacket, using C, but address not impl(src port %d, dst port %d, proto :%d)", PacketHeaderInfo.PortLocal, PacketHeaderInfo.PortRemote, PacketHeaderInfo.IpProtocol)

			} else {
				status := PacketHeaderInfo.ParseErrorCode
				return nil, nil, fmt.Errorf("Error code %d: %s, %w", PacketHeaderInfo.ParseErrorCode, C.GoString(C.ParsePacketStatusToString(status)), ErrNotSupported)
			}
		} else {
			return nil, nil, fmt.Errorf("Failed to parse with gopacket, error: %w", err)
		}
	}

	timestamp := C.LargeIntegerToInt(StreamMetaData.TimeStamp)

	var verdict flow.Verdict
	if StreamMetaData.DropReason != 0 {
		verdict = flow.Verdict_DROPPED
	} else {
		verdict = flow.Verdict_FORWARDED
	}

	meta := &Metadata{
		Timestamp:     int64(timestamp),
		ComponentID:   uint32(StreamMetaData.ComponentId),
		DropReason:    uint32(StreamMetaData.DropReason),
		PayloadLength: uint64(payloadLength),
		Verdict:       verdict,
	}

	return packet, meta, nil
}

func (w *WinPktMon) parseWithGoPacket(buffer []byte, StreamMetaData C.PACKETMONITOR_STREAM_METADATA_RETINA) (*Packet, error) {
	var packet gopacket.Packet
	// construct a 5 tuple showing src, dest ip and port
	if StreamMetaData.PacketType == 1 {
		packet = gopacket.NewPacket(buffer, layers.LayerTypeEthernet, gopacket.NoCopy)
	} else if StreamMetaData.PacketType == 3 {
		packet = gopacket.NewPacket(buffer, layers.LayerTypeIPv4, gopacket.Default)
	} else {
		return nil, fmt.Errorf("Failed to create packet: %w", ErrUnknownPacketType)
	}

	// surely there is a better struct somewhere to hold fivetuple
	var minpacket Packet

	// get IP layer from packet (src/dst ip address)
	ip := &layers.IPv4{}
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ = ipLayer.(*layers.IPv4)
	} else {
		return nil, fmt.Errorf("Failed to parse IP layer %w", ErrFailedToParseWithGoPacket)
	}

	minpacket.SourceIP = ip.SrcIP
	minpacket.DestIP = ip.DstIP

	// get protocol layer from packet (src/dst port)
	tcp := &layers.TCP{}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ = tcpLayer.(*layers.TCP)

		if tcp.SYN {
			minpacket.syn = 1
		}
		if tcp.ACK {
			minpacket.ack = 1
		}
		if tcp.FIN {
			minpacket.fin = 1
		}
		if tcp.RST {
			minpacket.rst = 1
		}
		if tcp.PSH {
			minpacket.psh = 1
		}
		if tcp.URG {
			minpacket.urg = 1
		}

		minpacket.SourcePort = uint32(tcp.SrcPort)
		minpacket.DestPort = uint32(tcp.DstPort)
		minpacket.Protocol = 6
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		minpacket.SourcePort = uint32(udp.SrcPort)
		minpacket.DestPort = uint32(udp.DstPort)
		minpacket.Protocol = 17
	} else {
		return nil, fmt.Errorf("No TCP/UDP layer found %w", ErrFailedToParseWithGoPacket)
	}

	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		var as, qs []string
		for _, a := range dns.Answers {
			as = append(as, a.String())
		}
		for _, q := range dns.Questions {
			qs = append(qs, string(q.Name))
		}

		//w.l.Debug("DNS Packet", zap.String("src", minpacket.SourceIP.String()), zap.String("dst", minpacket.DestIP.String()), zap.Strings("query", qs), zap.Strings("answer", as))
	}

	return &minpacket, nil
}
