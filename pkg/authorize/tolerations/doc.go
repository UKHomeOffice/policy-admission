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
	core "k8s.io/kubernetes/pkg/apis/core"
)

const (
	// Name is the name of the authorizer
	Name = "tolerations"
	// Annotation is the namespace annotation used to control taints whitelist
	Annotation = "policy-admission.acp.homeoffice.gov.uk/" + Name
)

// Config is the configuration for the taint authorizer
type Config struct {
	// IgnoreNamespaces is list of namespace to
	IgnoreNamespaces []string `yaml:"ignored-namespaces" json:"ignored-namespaces"`
	// DefaultWhitelist is default whitelist applied to all unless a namespace has one
	DefaultWhitelist []core.Toleration `yaml:"default-whitelist" json:"default-whitelist"`
}

// NewDefaultConfig is the default configuration
func NewDefaultConfig() *Config {
	return &Config{
		IgnoreNamespaces: []string{"kube-system", "kube-admission"},
	}
}
