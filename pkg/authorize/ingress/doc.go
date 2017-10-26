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

package ingress

const (
	// Name is the name of the authorizer
	Name = "ingress"
	// Annotation is the namespace annotation used to control taints whitelist
	Annotation = "policy-admission.acp.homeoffice.gov.uk/" + Name
)

// Config is the configuration for the authorizer
type Config struct {
	// EnforceTLS indicated we should enforce TLS between pods and ingress
	EnforceTLS bool `yaml:"enforce-tls" json:"enforce-tls"`
	// IgnoreNamespaces is list of namespace to
	IgnoreNamespaces []string `yaml:"ignored-namespaces" json:"ignored-namespaces"`
	// TLSAnnotation is the ingress annotation used to indicates secure backend
	TLSAnnontation string `yaml:"tls-annotation" json:"tls-annotation"`
}

// NewDefaultConfig is the default configuration
func NewDefaultConfig() *Config {
	return &Config{
		EnforceTLS:       true,
		IgnoreNamespaces: []string{"kube-system", "kube-public"},
		TLSAnnontation:   "kubernetes/ingress/secure-backends",
	}
}
