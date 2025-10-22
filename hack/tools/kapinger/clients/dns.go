package clients

import (
	"context"
	"log/slog"
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
			slog.Info("DNS client context done")
			return nil
		case <-ticker.C:
			go func() {
				for i := 0; i < k.volume; i++ {
					ips, err := net.LookupIP(k.address)
					if err != nil {
						slog.Error("dns client: could not get IPs", "error", err, "address", k.address)
						return
					}
					slog.Info("dns client: resolved address", "address", k.address, "ips", ips)
				}
			}()
		}
	}
}
