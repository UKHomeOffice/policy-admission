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

package kubecertmanager

import "os"

const (
	// Name is the name of the authorizer
	Name = "kubecertmanager"
	// EnableDNSCheck annontation controls the dns checker
	EnableDNSCheck = Name + "/enable-dns-check"
)

const (
	kubeCertAccessID = "KUBE_CERT_ACCESS_ID"
	kubeCertSecretID = "KUBE_CERT_SECRET_KEY"
)

// Config is the configuration for the service
type Config struct {
	// ExternalIngressHostname is the dns hostname which external ingresses should be pointing to
	ExternalIngressHostname string `yaml:"external-ingress-hostname" json:"external-ingress-hostname"`
	// IgnoredNamespaces is a list namespaces to ignore
	IgnoreNamespaces []string `yaml:"ignored-namespaces" json:"ignored-namespaces"`
	// HostedDomains is a list of hosted domains we can add records for
	HostedDomains []string `yaml:"hosted-domains" json:"hosted-domains"`
}

// NewDefaultConfig returns a default config
func NewDefaultConfig() *Config {
	return &Config{
		IgnoreNamespaces: []string{"kube-system", "kube-admission"},
	}
}

// UseRoute53Check checks if we are using the listing of the hosting domains
func (c *Config) UseRoute53Check() bool {
	return os.Getenv(kubeCertAccessID) != "" && os.Getenv(kubeCertSecretID) != ""
}
