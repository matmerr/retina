package config

import (
	"log"
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

	EnvHTTPPort         = "HTTP_PORT"
	EnvTCPPort          = "TCP_PORT"
	EnvUDPPort          = "UDP_PORT"
	EnvBurstVolume      = "BURST_VOLUME"
	EnvBurstInterval    = "BURST_INTERVAL_MS"
	EnvDNSClientEnabled = "DNS_CLIENT_ENABLED"
	EnvDNSClientAddress = "DNS_CLIENT_ADDRESS"
	EnvMeshClientEnabled = "MESH_CLIENT_ENABLED"
)

// just basic homebrew config, no viper/cobra to keep binary tiny
type KapingerConfig struct {
	BurstVolume      int
	BurstInterval    time.Duration
	HTTPPort         int
	TCPPort          int
	UDPPort          int
	DNSClientEnabled bool
	DNSClientAddress string
	MeshClientEnabled bool
}

// configmap later, but for now env is fine
func LoadConfigFromEnv() *KapingerConfig {
	k := &KapingerConfig{}
	var err error

	k.TCPPort, err = strconv.Atoi(os.Getenv(EnvTCPPort))
	if err != nil {
		k.TCPPort = defaultTCPPort
		log.Printf("%s not set, defaulting to port %d\n", EnvTCPPort, defaultTCPPort)
	}

	k.UDPPort, err = strconv.Atoi(os.Getenv(EnvUDPPort))
	if err != nil {
		k.UDPPort = defaultUDPPort
		log.Printf("%s not set, defaulting to port %d\n", EnvUDPPort, defaultUDPPort)
	}

	k.HTTPPort, err = strconv.Atoi(os.Getenv(EnvHTTPPort))
	if err != nil {
		k.HTTPPort = defaultHTTPPort
		log.Printf("%s not set, defaulting to port %d\n", EnvHTTPPort, defaultHTTPPort)
	}

	k.BurstVolume, err = strconv.Atoi(os.Getenv(EnvBurstVolume))
	if err != nil {
		k.BurstVolume = defaultBurstVolume
		log.Printf("%s not set, defaulting to %d\n", EnvBurstVolume, defaultBurstVolume)
	} else {
		log.Printf("%s set to: %d\n", EnvBurstVolume, k.BurstVolume)
	}

	burstInterval, err := strconv.Atoi(os.Getenv(EnvBurstInterval))
	if err != nil {
		k.BurstInterval = defaultBurstInterval
		log.Printf("%s not set, defaulting to %d\n", EnvBurstInterval, defaultBurstInterval)
	} else {
		k.BurstInterval = time.Duration(burstInterval) * time.Millisecond
		log.Printf("%s set to: %s\n", EnvBurstInterval, k.BurstInterval)
	}

	k.DNSClientEnabled, err = strconv.ParseBool(os.Getenv(EnvDNSClientEnabled))
	if err != nil {
		k.DNSClientEnabled = false
		log.Printf("%s not set or invalid, defaulting to false\n", EnvDNSClientEnabled)
	} else {
		log.Printf("%s set to: %t\n", EnvDNSClientEnabled, k.DNSClientEnabled)
	}

	k.DNSClientAddress = os.Getenv(EnvDNSClientAddress)
	if k.DNSClientAddress == "" {
		k.DNSClientAddress = defaultDNSAddress
		log.Printf("%s not set, defaulting to %s\n", EnvDNSClientAddress, defaultDNSAddress)
	} else {
		log.Printf("%s set to: %s\n", EnvDNSClientAddress, k.DNSClientAddress)
	}

	k.MeshClientEnabled, err = strconv.ParseBool(os.Getenv(EnvMeshClientEnabled))
	if err != nil {
		k.MeshClientEnabled = false
		log.Printf("%s not set or invalid, defaulting to false\n", EnvMeshClientEnabled)
	} else {
		log.Printf("%s set to: %t\n", EnvMeshClientEnabled, k.MeshClientEnabled)
	}

	return k
}
