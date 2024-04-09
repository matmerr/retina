package pktmon

// #cgo CFLAGS: -I packetmonitorsupport
// #cgo LDFLAGS: -L packetmonitorsupport
// #cgo LDFLAGS: -lpktmonapi -lws2_32
//
// #include "PacketMonitor.h"
// #include "packetmonitorpacket.h"
// #include "packetmonitorsupportutil.h"
// #include "packetmonitorsupport.h"
// #include "packetmonitorsupport.c"
// #include "packetmonitorpacketparse.c"
import "C"
import (
	"errors"
	"fmt"
	golog "log"
	"unsafe"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/metrics"
)

var (
	ErrFailedToParseWithGoPacket  error = fmt.Errorf("Failed to parse with gopacket")
	ErrNotSupported               error = fmt.Errorf("Not supported")
	ErrFailedToStartPacketCapture error = fmt.Errorf("Failed to start pktmon packet capture")
	ErrUnknownPacketType          error = fmt.Errorf("Unknown packet type")

	VarDefaultBufferMultiplier = 10

	TruncationSize = 128
)

type WinPktMon struct {
	l *log.ZapLogger
}

func (w *WinPktMon) Initialize() error {
	var UserContext C.PACKETMONITOR_STREAM_EVENT_INFO

	// calling packet capture routine concurrently
	fmt.Println("Starting (go)")
	trunc := C.int(TruncationSize)
	result := C.InitializePacketCapture(unsafe.Pointer(&UserContext), C.int(VarDefaultBufferMultiplier), trunc)
	if result != 0 {
		return fmt.Errorf("Error code %d, %w   ", result, ErrFailedToStartPacketCapture)
	}

	return nil
}

var usenextpacket = true

func (w *WinPktMon) GetNextPacket() (*Packet, *Metadata, error) {
	buffer := make([]byte, 5000)
	var bufferSize C.int = 5000 // Windows LSO MTU size, Pktmon ring buffers size in Pktmon dll is (64 * 4kb)

	// Three memory buffers
	// - Streaming feature descripter buffer
	// - Descripter buffer
	// - actual packet buffer (64 * 4kb)
	var payloadLength C.int = 0
	var StreamMetaData C.PACKETMONITOR_STREAM_METADATA_RETINA
	var PacketHeaderInfo C.PACKETMONITOR_PACKET_HEADER_INFO
	var MissedPacketsWrite C.int = 0 // packets getting missed in the driver
	var MissedPacketsRead C.int = 0  // packets getting missed in the driver

	// Call the operation in a goroutine

	if usenextpacket {
		C.GetNextPacket((*C.uchar)(unsafe.Pointer(&buffer[0])), bufferSize, &payloadLength, &StreamMetaData, &PacketHeaderInfo, &MissedPacketsWrite, &MissedPacketsRead)
	} else {
		//
		C.GetNextPacketArr((*C.uchar)(unsafe.Pointer(&buffer[0])), bufferSize, &payloadLength, &StreamMetaData, &PacketHeaderInfo, &MissedPacketsWrite, &MissedPacketsRead)
	}

	//	golog.Printf("Payload length: %d \n", int(payloadLength))

	if int(MissedPacketsRead) > 0 {
		golog.Printf("Missed packets read: %d\n", int(MissedPacketsRead))
	}

	if int(MissedPacketsWrite) > 0 {
		golog.Printf("Missed packets write: %d\n", int(MissedPacketsWrite))
	}

	// Use select to wait for either the operation to complete or the context to timeout

	packet, err := w.parseWithGoPacket(buffer, StreamMetaData)
	if err != nil {
		//fmt.Printf("Failed to parse with gopacket, using with error %v\n", err)
		if errors.Is(err, ErrFailedToParseWithGoPacket) {

			if PacketHeaderInfo.ParseErrorCode == 0 {

				//fmt.Printf("Packet Source IP: %d\n", PacketHeaderInfo.SourceAddressV4)
				//fmt.Printf("Packet Destination IP: %d\n", PacketHeaderInfo.DestinationAddressV4)
				//fmt.Printf("Packet Source Port: %d\n", PacketHeaderInfo.PortLocal)
				//fmt.Printf("Packet Destination Port: %d\n", PacketHeaderInfo.PortRemote)
				//fmt.Printf("Packet Protocol: %d\n", PacketHeaderInfo.IpProtocol)
				//fmt.Printf("Packet Direction: %d\n", StreamMetaData.DirectionName)
				//fmt.Printf("Packet Drop Reason %d\n", StreamMetaData.DropReason)
				//fmt.Printf("Packet Drop Location %d\n", StreamMetaData.DropLocation)

				if StreamMetaData.DropReason != 0 {
					fmt.Printf("Packet dropped from srcport %d to dstport %d, proto: %d, dropreason %d\n",
						//PacketHeaderInfo.SourceAddressV4,
						PacketHeaderInfo.PortLocal,
						//PacketHeaderInfo.DestinationAddressV4,
						PacketHeaderInfo.PortRemote,
						PacketHeaderInfo.IpProtocol,
						StreamMetaData.DropReason)
				}

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
			return nil, nil, fmt.Errorf("Failed to parse with gopacket: %w", err)
		}
	}

	var timestampint C.longlong

	//golog.Printf("C timestamp: %d", StreamMetaData.TimeStamp)
	C.LargeIntegerToInt(StreamMetaData.TimeStamp, &timestampint)
	//golog.Printf("LargeIntegerToInt:   %d", timestampint)
	timestamp := int64(timestampint)
	//golog.Printf("Go timestamp: %d", int64(timestamp))

	// convert from windows to unix time
	var epochDifference int64 = 116444736000000000
	var unixTime int64 = (timestamp - epochDifference) / 10000000

	// Create a Time struct from the Unix time
	//timestampunix := time.Unix(unixTime, 0)

	// Print the time in a human-readable format
	//golog.Printf("Time: %s\n", t.Format(time.RFC3339))

	var verdict flow.Verdict
	if StreamMetaData.DropReason != 0 {
		verdict = flow.Verdict_DROPPED
		fmt.Printf("Packet dropped from %s:%d to %s:%d, proto: %d, \t dropreason %s\n", packet.SourceIP, packet.SourcePort, packet.DestIP, packet.DestPort, packet.Protocol, metrics.GetDropReason(uint32(StreamMetaData.DropReason)))
	} else {
		verdict = flow.Verdict_FORWARDED
	}

	meta := &Metadata{
		Timestamp:     int64(unixTime),
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
		return nil, ErrUnknownPacketType
	}

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

		minpacket.syn = tcp.SYN
		minpacket.ack = tcp.ACK
		minpacket.fin = tcp.FIN
		minpacket.rst = tcp.RST
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

		//fmt.Printf("DNS Packet, src:%s, dst: %s,  query: %+v, answer: %+v\n", minpacket.SourceIP, minpacket.DestIP, qs, as)
		minpacket.dns = dns
	}

	return &minpacket, nil
}
