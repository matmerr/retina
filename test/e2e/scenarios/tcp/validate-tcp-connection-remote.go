package flow

import (
	"fmt"
	"log"

	prom "github.com/microsoft/retina/test/e2e/framework/prometheus"
	"github.com/microsoft/retina/test/e2e/framework/types"
)

var tcpConnectionRemoteMetricName = "networkobservability_tcp_connection_remote"

const (
	address = "address"
	port    = "port"
)

type ValidateRetinaTCPConnectionRemoteMetric struct {
	PortForwardedRetinaPort string
}

func (v *ValidateRetinaTCPConnectionRemoteMetric) Run(_ *types.RuntimeObjects) error {
	promAddress := fmt.Sprintf("http://localhost:%s/metrics", v.PortForwardedRetinaPort)

	validMetrics := []map[string]string{
		{address: "0.0.0.0", port: "0"},
	}

	for _, metric := range validMetrics {
		err := prom.CheckMetric(promAddress, tcpConnectionRemoteMetricName, metric)
		if err != nil {
			return fmt.Errorf("failed to verify prometheus metrics: %w", err)
		}
	}

	log.Printf("found metrics matching %+v\n", validMetrics)
	return nil
}

func (v *ValidateRetinaTCPConnectionRemoteMetric) PreRun() error {
	return nil
}

func (v *ValidateRetinaTCPConnectionRemoteMetric) Stop() error {
	return nil
}
