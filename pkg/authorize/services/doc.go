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

package services

import (
	core "k8s.io/api/core/v1"
)

const (
	// Name is the name of the authorizer
	Name = "services"
)

// Config is the configuration for the taint authorizer
type Config struct {
	// IgnoreNamespaces is list of namespace to
	IgnoreNamespaces []string `yaml:"ignored-namespaces" json:"ignored-namespaces"`
	// Whitelist is default whitelist applied to all namespaces
	Whitelist []string `yaml:"whitelist" json:"whitelist"`
}

// NewDefaultConfig is the default configuration
func NewDefaultConfig() *Config {
	return &Config{
		IgnoreNamespaces: []string{"kube-system", "kube-admission"},
		Whitelist:        []string{string(core.ServiceTypeNodePort), string(core.ServiceTypeClusterIP)},
	}
}
