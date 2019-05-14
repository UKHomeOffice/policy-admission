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

package tolerations

import (
	core "k8s.io/api/core/v1"
)

const (
	// Name is the name of the authorizer
	Name = "tolerations"
)

// Config is the configuration for the taint authorizer
type Config struct {
	// IgnoreNamespaces is list of namespace to
	IgnoreNamespaces []string `yaml:"ignore-namespaces" json:"ignore-namespaces"`
	// IgnoreNamespaceLabels is a list keypairs to ignore
	IgnoreNamespaceLabels map[string]string `yaml:"ignore-namespace-labels" json:"ignore-namespace-labels"`
	// DefaultWhitelist is default whitelist applied to all unless a namespace has one
	DefaultWhitelist []core.Toleration `yaml:"default-whitelist" json:"default-whitelist"`
}

// NewDefaultConfig is the default configuration
func NewDefaultConfig() *Config {
	return &Config{
		IgnoreNamespaces: []string{"kube-system", "kube-admission"},
	}
}
