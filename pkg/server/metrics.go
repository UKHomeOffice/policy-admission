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

package server

import "github.com/prometheus/client_golang/prometheus"

var (
	admissionRequestLatencyMetric = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "admission_request_latency_sec",
			Help: "The HTTP request latency for incoming policy requests",
		},
	)
	admissionErrorMetric = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "admission_error_total",
			Help: "The number of errors encountered by the admission controller",
		},
	)
	admissionTotalMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "admission_action_total",
			Help: "A breakdown of the policy actions taken by the admission controller",
		},
		[]string{"action"},
	)
	admissionAuthorizerActionMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "admission_authorizer_action_total",
			Help: "A summary of the decisions broken down by authorizer",
		},
		[]string{"authorizer", "action"},
	)
	admissionAuthorizerLatencyMetric = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "admission_latency_sec",
			Help: "The latency broken down by authorizer in seconds",
		},
		[]string{"authorizer"},
	)
)

func init() {
	prometheus.MustRegister(admissionAuthorizerActionMetric)
	prometheus.MustRegister(admissionAuthorizerLatencyMetric)
	prometheus.MustRegister(admissionErrorMetric)
	prometheus.MustRegister(admissionRequestLatencyMetric)
	prometheus.MustRegister(admissionTotalMetric)
}
