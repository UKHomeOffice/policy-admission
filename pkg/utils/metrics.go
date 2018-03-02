/*
Copyright 2018 Home Office All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	cacheHitMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cache_hits_total",
			Help: "A summary of the cache usage, hits and misses",
		},
		[]string{"hit"},
	)
	cacheLatencyMetric = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "cache_latency_secs",
			Help: "A summary of the latency for non-cached operations",
		},
	)
)

func init() {
	prometheus.MustRegister(cacheHitMetric)
	prometheus.MustRegister(cacheLatencyMetric)
}
