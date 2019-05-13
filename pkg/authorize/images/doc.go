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

package images

const (
	// Name is the name of the authorizer
	Name = "images"
)

// Config is the configuration for the service
type Config struct {
	// IgnoredNamespaces is a list namespaces to ignore
	IgnoreNamespaces []string `yaml:"ignored-namespaces" json:"ignored-namespaces"`
	// IgnoreNamespaceLabels is a list keypairs to ignore
	IgnoreNamespaceLabels map[string]string `yaml:"ignore-namespace-labels" json:"ignore-namespace-labels"`
	// ImagePolicies is a collection of regexs
	ImagePolicies []string `yaml:"image-policies" json:"image-policies"`
}

// NewDefaultConfig returns a default config
func NewDefaultConfig() *Config {
	return &Config{
		IgnoreNamespaces: []string{"kube-system", "kube-admission"},
	}
}
