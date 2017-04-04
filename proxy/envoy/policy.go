// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Functions related to translation from the control policies to Envoy config
// Policies apply to Envoy upstream clusters but may appear in the route section.

package envoy

import (
	"sort"
	"strings"

	proxyconfig "istio.io/api/proxy/v1/config"
	"istio.io/manager/model"
)

func insertMixerFilter(listeners []*Listener, instances []*model.ServiceInstance, context *ProxyContext) {
	if context.MeshConfig.MixerAddress == "" {
		return
	}

	// join IPs with a comma
	ips := make([]string, 0)
	for ip := range context.Addrs {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	id := strings.Join(ips, ",")

	// join service names with a comma
	serviceSet := make(map[string]bool)
	for _, instance := range instances {
		serviceSet[instance.Service.Hostname] = true
	}
	services := make([]string, 0)
	for service := range serviceSet {
		services = append(services, service)
	}
	sort.Strings(services)
	service := strings.Join(services, ",")

	for _, l := range listeners {
		for _, f := range l.Filters {
			if f.Name == HTTPConnectionManager {
				http := (f.Config).(*HTTPFilterConfig)
				http.Filters = append([]HTTPFilter{{
					Type: "decoder",
					Name: "mixer",
					Config: &FilterMixerConfig{
						MixerServer: context.MeshConfig.MixerAddress,
						MixerAttributes: map[string]string{
							"target.uid":     id,
							"target.service": service,
						},
						ForwardAttributes: map[string]string{
							"source.uid":     id,
							"source.service": service,
						},
					},
				}}, http.Filters...)
			}
		}
	}
}

// insertDestinationPolicy assumes an outbound cluster and inserts custom configuration for the cluster
func insertDestinationPolicy(config *model.IstioRegistry, cluster *Cluster) {
	// TODO: this has to be a singleton. Cannot have multiple dst policies
	for _, policy := range config.DestinationPolicies(cluster.hostname, cluster.tags) {
		if policy.LoadBalancing != nil {
			switch policy.LoadBalancing.GetName() {
			case proxyconfig.LoadBalancing_ROUND_ROBIN:
				cluster.LbType = LbTypeRoundRobin
			case proxyconfig.LoadBalancing_LEAST_CONN:
				cluster.LbType = "least_request"
			case proxyconfig.LoadBalancing_RANDOM:
				cluster.LbType = "random"
			}
		}

		// Set up circuit breakers and outlier detection
		if policy.CircuitBreaker != nil && policy.CircuitBreaker.GetSimpleCb() != nil {
			cbconfig := policy.CircuitBreaker.GetSimpleCb()
			cluster.MaxRequestsPerConnection = int(cbconfig.HttpMaxRequestsPerConnection)

			// Envoy's circuit breaker is a combination of its circuit breaker (which is actually a bulk head)
			// outlier detection (which is per pod circuit breaker)
			cluster.CircuitBreaker = &CircuitBreaker{}
			if cbconfig.MaxConnections > 0 {
				cluster.CircuitBreaker.Default.MaxConnections = int(cbconfig.MaxConnections)
			}
			if cbconfig.HttpMaxRequests > 0 {
				cluster.CircuitBreaker.Default.MaxRequests = int(cbconfig.HttpMaxRequests)
			}
			if cbconfig.HttpMaxPendingRequests > 0 {
				cluster.CircuitBreaker.Default.MaxPendingRequests = int(cbconfig.HttpMaxPendingRequests)
			}
			//TODO: need to add max_retries as well. Currently it defaults to 3

			cluster.OutlierDetection = &OutlierDetection{}

			cluster.OutlierDetection.MaxEjectionPercent = 10
			if cbconfig.SleepWindowSeconds > 0 {
				cluster.OutlierDetection.BaseEjectionTimeMS = int(cbconfig.SleepWindowSeconds * 1000)
			}
			if cbconfig.HttpConsecutiveErrors > 0 {
				cluster.OutlierDetection.ConsecutiveErrors = int(cbconfig.HttpConsecutiveErrors)
			}
			if cbconfig.HttpDetectionIntervalSeconds > 0 {
				cluster.OutlierDetection.IntervalMS = int(cbconfig.HttpDetectionIntervalSeconds * 1000)
			}
			if cbconfig.HttpMaxEjectionPercent > 0 {
				cluster.OutlierDetection.MaxEjectionPercent = int(cbconfig.HttpMaxEjectionPercent)
			}
		}
	}
}
