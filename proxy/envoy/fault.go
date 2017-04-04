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
	proxyconfig "istio.io/api/proxy/v1/config"
)

// buildFaultFilters builds a list of fault filters for the http route
func buildFaultFilters(routeConfig *HTTPRouteConfig) []HTTPFilter {
	if routeConfig == nil {
		return nil
	}

	faults := make([]HTTPFilter, 0)
	for _, f := range routeConfig.faults() {
		faults = append(faults, *f)
	}

	return faults
}

// buildFaultFilter builds a single fault filter for envoy cluster
func buildHTTPFaultFilter(cluster string, faultRule *proxyconfig.HTTPFaultInjection, headers Headers) *HTTPFilter {
	return &HTTPFilter{
		Type: "decoder",
		Name: "fault",
		Config: FilterFaultConfig{
			UpstreamCluster: cluster,
			Headers:         headers,
			Abort:           buildAbortConfig(faultRule.Abort),
			Delay:           buildDelayConfig(faultRule.Delay),
		},
	}
}

// buildAbortConfig builds the envoy config related to abort spec in a fault filter
func buildAbortConfig(abortRule *proxyconfig.HTTPFaultInjection_Abort) *AbortFilter {
	if abortRule == nil || abortRule.GetHttpStatus() == 0 || abortRule.Percent == 0.0 {
		return nil
	}

	return &AbortFilter{
		Percent:    int(abortRule.Percent),
		HTTPStatus: int(abortRule.GetHttpStatus()),
	}
}

// buildDelayConfig builds the envoy config related to delay spec in a fault filter
func buildDelayConfig(delayRule *proxyconfig.HTTPFaultInjection_Delay) *DelayFilter {
	if delayRule == nil || delayRule.GetFixedDelaySeconds() == 0.0 || delayRule.Percent == 0.0 {
		return nil
	}

	return &DelayFilter{
		Type:     "fixed",
		Percent:  int(delayRule.Percent),
		Duration: int(delayRule.GetFixedDelaySeconds() * 1000),
	}
}
