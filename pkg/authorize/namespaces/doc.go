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

package namespaces

const (
	// Name is the name of the authorizer
	Name = "namespaces"
	// Annotation provides a namespace specific override or add to policy
	Annotation = "policy-admission.acp.homeoffice.gov.uk/" + Name
)

// NamespaceAnnotation defines a required annotation
type NamespaceAnnotation struct {
	// Required indicate the labels is required

}

// Config is the configuration for the service
type Config struct {
	// IgnoredNamespaces is a list namespaces to ignore
	IgnoreNamespaces []string
}

// NewDefaultConfig returns a default config
func NewDefaultConfig() *Config {
	return &Config{
		IgnoreNamespaces: []string{"kube-system", "kube-admission"},
	}
}
