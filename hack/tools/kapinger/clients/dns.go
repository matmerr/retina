package clients

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"
)

type KapingerDNSClient struct {
	volume   int
	interval time.Duration
	address  string
}

func NewKapingerDNSClient(volume int, interval time.Duration, address string) *KapingerDNSClient {
	return &KapingerDNSClient{
		interval: time.Duration(interval),
		volume:   volume,
		address:  address,
	}
}

func (k *KapingerDNSClient) MakeRequests(ctx context.Context) error {
	ticker := time.NewTicker(k.interval)
	for {
		select {
		case <-ctx.Done():
			log.Printf("DNS client context done")
			return nil
		case <-ticker.C:
			go func() {
				for i := 0; i < k.volume; i++ {
					ips, err := net.LookupIP(k.address)
					if err != nil {
						fmt.Printf("dns client: could not get IPs: %v\n", err)
						return
					}
					log.Printf("dns client: resolved %s to %s\n", k.address, ips)
				}
			}()
		}
	}
}
