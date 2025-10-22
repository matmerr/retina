package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"time"

	"github.com/microsoft/retina/hack/tools/kapinger/clients"
	"github.com/microsoft/retina/hack/tools/kapinger/config"
	"github.com/microsoft/retina/hack/tools/kapinger/servers"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	// Initialize slog with JSON handler for structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("starting kapinger")
	clientset, err := getKubernetesClientSet()
	if err != nil {
		slog.Error("failed to get kubernetes clientset", "error", err)
		os.Exit(1)
	}

	cfg := config.LoadConfigFromEnv()

	ctx := context.Background()
	go servers.StartAll(ctx, cfg)

	var kapingerClients []clients.Client

	// Create a mesh client (Kubernetes service discovery based HTTP client)
	if cfg.MeshClientEnabled {
		meshclient, err := clients.NewKapingerMeshClient(clientset, "app=kapinger", cfg.BurstVolume, cfg.BurstInterval, cfg.HTTPPort)
		if err != nil {
			slog.Error("failed to create mesh client", "error", err)
			os.Exit(1)
		}
		kapingerClients = append(kapingerClients, meshclient)
		slog.Info("mesh client enabled")
	} else {
		slog.Info("mesh client disabled")
	}

	// create and append a DNS client
	if cfg.DNSClientEnabled {
		dnsclient := clients.NewKapingerDNSClient(cfg.BurstVolume, cfg.BurstInterval, cfg.DNSClientAddress)
		kapingerClients = append(kapingerClients, dnsclient)
		slog.Info("DNS client enabled", "address", cfg.DNSClientAddress)
	} else {
		slog.Info("DNS client disabled")
	}

	// create and append an HTTP client (simple URL-based HTTP client)
	if cfg.HTTPClientEnabled {
		httpclient := clients.NewKapingerHTTPClient(cfg.BurstVolume, cfg.BurstInterval, cfg.HTTPClientURL)
		kapingerClients = append(kapingerClients, httpclient)
		slog.Info("HTTP client enabled", "url", cfg.HTTPClientURL)
	} else {
		slog.Info("HTTP client disabled")
	}

	// Initialize the random number generator with a seed based on the current time
	rand.New(rand.NewSource(time.Now().UnixNano()))

	// Generate a random number between 1 and 1000 for delay jitter
	jitter := rand.Intn(100) + 1
	time.Sleep(time.Duration(jitter) * time.Millisecond)

	g, gCtx := errgroup.WithContext(ctx)

	for _, client := range kapingerClients {
		client := client
		g.Go(func() error {
			err = client.MakeRequests(gCtx)
			if err != nil {
				return fmt.Errorf("error making request: %w", err)
			}
			return nil
		})
	}
	err = g.Wait()
	if err != nil {
		slog.Error("error making request", "error", err)
		os.Exit(1)
	}
}

func getKubernetesClientSet() (*kubernetes.Clientset, error) {
	// Use the in-cluster configuration
	config, err := rest.InClusterConfig()
	if err != nil {
		slog.Error("error getting in-cluster config", "error", err)
		return nil, err
	}

	// Create a Kubernetes clientset using the in-cluster configuration
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		slog.Error("error creating clientset", "error", err)
		return nil, err
	}
	return clientset, nil
}
