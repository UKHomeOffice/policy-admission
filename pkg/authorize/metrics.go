/*
Copyright 2017 Home Office All rights reserved.

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

package authorize

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	configReloadMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "config_reload_total",
			Help: "A counter of the total reloads for authorizer configuration files",
		},
		[]string{"filename"},
	)
	configReloadErrorMetrics = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "config_reload_error_total",
			Help: "The total amount of errors per configuration file when reloading",
		},
		[]string{"filename"},
	)
)

func init() {
	prometheus.MustRegister(configReloadErrorMetrics)
	prometheus.MustRegister(configReloadMetric)
}
