package config

import (
	"log/slog"
	"os"
	"strconv"
	"time"
)

const (
	defaultHTTPPort      = 8080
	defaultTCPPort       = 8085
	defaultUDPPort       = 8086
	defaultBurstVolume   = 1
	defaultBurstInterval = 500 * time.Millisecond
	defaultDNSAddress    = "retina.sh"
	defaultHTTPURL       = "http://www.example.com"

	EnvHTTPPort          = "HTTP_PORT"
	EnvTCPPort           = "TCP_PORT"
	EnvUDPPort           = "UDP_PORT"
	EnvBurstVolume       = "BURST_VOLUME"
	EnvBurstInterval     = "BURST_INTERVAL_MS"
	EnvDNSClientEnabled  = "DNS_CLIENT_ENABLED"
	EnvDNSClientAddress  = "DNS_CLIENT_ADDRESS"
	EnvHTTPClientEnabled = "HTTP_CLIENT_ENABLED"
	EnvHTTPClientURL     = "HTTP_CLIENT_URL"
	EnvMeshClientEnabled = "MESH_CLIENT_ENABLED"
)

// just basic homebrew config, no viper/cobra to keep binary tiny
type KapingerConfig struct {
	BurstVolume       int
	BurstInterval     time.Duration
	HTTPPort          int
	TCPPort           int
	UDPPort           int
	DNSClientEnabled  bool
	DNSClientAddress  string
	HTTPClientEnabled bool
	HTTPClientURL     string
	MeshClientEnabled bool
}

// configmap later, but for now env is fine
func LoadConfigFromEnv() *KapingerConfig {
	k := &KapingerConfig{}
	var err error

	k.TCPPort, err = strconv.Atoi(os.Getenv(EnvTCPPort))
	if err != nil {
		k.TCPPort = defaultTCPPort
		slog.Info("config loaded", "env", EnvTCPPort, "value", k.TCPPort, "default", true)
	}

	k.UDPPort, err = strconv.Atoi(os.Getenv(EnvUDPPort))
	if err != nil {
		k.UDPPort = defaultUDPPort
		slog.Info("config loaded", "env", EnvUDPPort, "value", k.UDPPort, "default", true)
	}

	k.HTTPPort, err = strconv.Atoi(os.Getenv(EnvHTTPPort))
	if err != nil {
		k.HTTPPort = defaultHTTPPort
		slog.Info("config loaded", "env", EnvHTTPPort, "value", k.HTTPPort, "default", true)
	}

	k.BurstVolume, err = strconv.Atoi(os.Getenv(EnvBurstVolume))
	if err != nil {
		k.BurstVolume = defaultBurstVolume
		slog.Info("config loaded", "env", EnvBurstVolume, "value", k.BurstVolume, "default", true)
	} else {
		slog.Info("config loaded", "env", EnvBurstVolume, "value", k.BurstVolume)
	}

	burstInterval, err := strconv.Atoi(os.Getenv(EnvBurstInterval))
	if err != nil {
		k.BurstInterval = defaultBurstInterval
		slog.Info("config loaded", "env", EnvBurstInterval, "value", k.BurstInterval, "default", true)
	} else {
		k.BurstInterval = time.Duration(burstInterval) * time.Millisecond
		slog.Info("config loaded", "env", EnvBurstInterval, "value", k.BurstInterval)
	}

	k.DNSClientEnabled, err = strconv.ParseBool(os.Getenv(EnvDNSClientEnabled))
	if err != nil {
		k.DNSClientEnabled = false
		slog.Info("config loaded", "env", EnvDNSClientEnabled, "value", k.DNSClientEnabled, "default", true)
	} else {
		slog.Info("config loaded", "env", EnvDNSClientEnabled, "value", k.DNSClientEnabled)
	}

	k.DNSClientAddress = os.Getenv(EnvDNSClientAddress)
	if k.DNSClientAddress == "" {
		k.DNSClientAddress = defaultDNSAddress
		slog.Info("config loaded", "env", EnvDNSClientAddress, "value", k.DNSClientAddress, "default", true)
	} else {
		slog.Info("config loaded", "env", EnvDNSClientAddress, "value", k.DNSClientAddress)
	}

	k.HTTPClientEnabled, err = strconv.ParseBool(os.Getenv(EnvHTTPClientEnabled))
	if err != nil {
		k.HTTPClientEnabled = false
		slog.Info("config loaded", "env", EnvHTTPClientEnabled, "value", k.HTTPClientEnabled, "default", true)
	} else {
		slog.Info("config loaded", "env", EnvHTTPClientEnabled, "value", k.HTTPClientEnabled)
	}

	k.HTTPClientURL = os.Getenv(EnvHTTPClientURL)
	if k.HTTPClientURL == "" {
		k.HTTPClientURL = defaultHTTPURL
		slog.Info("config loaded", "env", EnvHTTPClientURL, "value", k.HTTPClientURL, "default", true)
	} else {
		slog.Info("config loaded", "env", EnvHTTPClientURL, "value", k.HTTPClientURL)
	}

	k.MeshClientEnabled, err = strconv.ParseBool(os.Getenv(EnvMeshClientEnabled))
	if err != nil {
		k.MeshClientEnabled = false
		slog.Info("config loaded", "env", EnvMeshClientEnabled, "value", k.MeshClientEnabled, "default", true)
	} else {
		slog.Info("config loaded", "env", EnvMeshClientEnabled, "value", k.MeshClientEnabled)
	}

	return k
}
