package pktmon

import (
	"context"
	"errors"
	"fmt"
	golog "log"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/google/gopacket/layers"
	kcfg "github.com/microsoft/retina/pkg/config"
	"github.com/microsoft/retina/pkg/enricher"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/metrics"
	"github.com/microsoft/retina/pkg/plugin/api"
	"github.com/microsoft/retina/pkg/utils"
)

var (
	ErrNilEnricher error = errors.New("enricher is nil")
)

const (
	Name = "pktmon"
)

type PktMonPlugin struct {
	enricher        enricher.EnricherInterface
	externalChannel chan *v1.Event
	pkt             PktMon
	l               *log.ZapLogger
}

func (p *PktMonPlugin) Compile(ctx context.Context) error {
	return nil
}

func (p *PktMonPlugin) Generate(ctx context.Context) error {
	return nil
}

func (p *PktMonPlugin) Init() error {
	p.pkt = &WinPktMon{
		l: log.Logger().Named(Name),
	}
	p.l = log.Logger().Named(Name)

	return nil
}

func (p *PktMonPlugin) Name() string {
	return "pktmon"
}

func (p *PktMonPlugin) SetupChannel(ch chan *v1.Event) error {
	p.externalChannel = ch
	return nil
}

func New(cfg *kcfg.Config) api.Plugin {
	return &PktMonPlugin{}
}

type DNSRequest struct {
	SourceIP      byte
	DestinationIP byte
}

func (p *PktMonPlugin) Start(ctx context.Context) error {
	fmt.Printf("setting up enricher since pod level is enabled \n")
	p.enricher = enricher.Instance()
	if p.enricher == nil {
		return ErrNilEnricher
	}

	// calling packet capture routine concurrently
	golog.Println("Starting (go)")
	err := p.pkt.Initialize()
	if err != nil {
		return fmt.Errorf("Failed to initialize pktmon: %v", err)
	}

	for {

		select {
		case <-ctx.Done():
			return fmt.Errorf("pktmon context cancelled: %v", ctx.Err())
		default:

			packet, metadata, err := p.pkt.GetNextPacket()
			if errors.Is(err, ErrNotSupported) {
				continue
			}

			if err != nil {
				golog.Printf("Error getting packet: %v\n", err)
				continue
			}

			fl := utils.ToFlow(
				metadata.Timestamp, // timestamp
				packet.SourceIP,
				packet.DestIP,
				packet.SourcePort,
				packet.DestPort,
				packet.Protocol,
				metadata.ComponentID, // observationPoint
				metadata.Verdict,     // flow.Verdict
			)
			//metadata.DropReason,  // flow.Direction
			//)

			if fl == nil {
				fmt.Println("error: flow is nil")
				continue
			}
			meta := &utils.RetinaMetadata{
				//DropReason: metadata.DropReason,
				Bytes: metadata.PayloadLength,
			}

			utils.AddPacketSize(meta, metadata.PayloadLength)

			utils.AddTcpFlagsBool(fl, packet.syn, packet.ack, packet.fin, packet.rst, packet.psh, packet.urg)

			if packet.dns != nil {
				//fmt.Printf("qType %d\n", packet.dns.OpCode)
				var qtype string
				switch packet.dns.OpCode {
				case layers.DNSOpCodeQuery:
					qtype = "Q"
				case layers.DNSOpCodeStatus:
					qtype = "R"
				default:
					qtype = "U"
				}

				var as, qs []string
				for _, a := range packet.dns.Answers {
					if a.IP != nil {
						as = append(as, a.IP.String())
					}
				}
				for _, q := range packet.dns.Questions {
					qs = append(qs, string(q.Name))
				}

				var query string
				if len(packet.dns.Questions) > 0 {
					query = string(packet.dns.Questions[0].Name[:])
				}

				fl.Verdict = utils.Verdict_DNS
				metad := &utils.RetinaMetadata{
					Bytes: metadata.PayloadLength,
				}
				utils.AddDNSInfo(fl, metad, qtype, uint32(packet.dns.ResponseCode), query, []string{qtype}, len(as), as)
				fmt.Printf("added dns info src %s, dst %s, to flow with qtype %s, qtypereal %d, response code src %d, query %s, answers %v, num answers %d num qs %d\n", packet.SourceIP.String(), packet.DestIP.String(), qtype, packet.dns.OpCode, packet.dns.ResponseCode, query, as, len(packet.dns.Answers), len(packet.dns.Questions))
			}

			ev := &v1.Event{
				Event:     fl,
				Timestamp: fl.Time,
			}
			if p.enricher != nil {
				// Create a context that will automatically cancel after a timeout

				//golog.Printf("writing flow - timestamp: %d, src %s, dst %s, src port %d, dst port %d, protocol %d, verdict %d, drop reason %d, payload length %d\n", metadata.Timestamp, packet.SourceIP.String(), packet.DestIP.String(), packet.SourcePort, packet.DestPort, packet.Protocol, metadata.Verdict, metadata.DropReason, metadata.PayloadLength)

				p.enricher.Write(ev)
				//	golog.Printf("wrote to enricher\n")

			} else {
				fmt.Printf("enricher is nil when writing\n")
			}

			// Write the event to the external channel.
			if p.externalChannel != nil {
				select {
				case p.externalChannel <- ev:
				default:
					// Channel is full, drop the event.
					// We shouldn't slow down the reader.
					metrics.LostEventsCounter.WithLabelValues(utils.ExternalChannel, string(Name)).Inc()
				}
			}
		}
	}
}

func (p *PktMonPlugin) Stop() error {
	return nil
}
