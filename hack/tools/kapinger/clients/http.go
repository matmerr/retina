package clients

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type KapingerHTTPClient struct {
	volume   int
	interval time.Duration
	url      string
	client   http.Client
}

func NewKapingerHTTPClient(volume int, interval time.Duration, url string) *KapingerHTTPClient {
	return &KapingerHTTPClient{
		interval: time.Duration(interval),
		volume:   volume,
		url:      url,
		client: http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
			Timeout:       2 * time.Second,
			CheckRedirect: nil, // Follow redirects (default behavior, up to 10 redirects)
		},
	}
}

func (k *KapingerHTTPClient) MakeRequests(ctx context.Context) error {
	ticker := time.NewTicker(k.interval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("HTTP client context done")
			return nil
		case <-ticker.C:
			go func() {
				for i := 0; i < k.volume; i++ {
					statusCode, err := k.makeRequest(ctx)
					if err != nil {
						slog.Error("http client: could not make request", "error", err, "url", k.url)
						return
					}
					slog.Info("http client: received response", "url", k.url, "status_code", statusCode)
				}
			}()
		}
	}
}

func (k *KapingerHTTPClient) makeRequest(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", k.url, http.NoBody)
	if err != nil {
		return 0, err
	}

	// Set the "Connection" header to "close"
	req.Header.Set("Connection", "close")

	// Send the request
	resp, err := k.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// Discard response body but ensure it's read to allow connection reuse
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		slog.Error("error discarding response body", "url", k.url, "error", err)
		return resp.StatusCode, err
	}

	return resp.StatusCode, nil
}
