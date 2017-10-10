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

package securitycontext

import (
	"errors"
	"fmt"

	core "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

const (
	// Name is the name of the authorizer
	Name = "securitycontext"
	// Annotation is the annotation which controls policy you can use
	Annotation = "policy-admission.acp.homeoffice.gov.uk/" + Name
)

// Config the security policies configuration
type Config struct {
	// Defaul is the name of the default policy to user
	Default string `yaml:"default"`
	// IgnoreNamespaces is a collection of namespace to bypass enforcement
	IgnoreNamespaces []string `yaml:"ignored-namespaces"`
	// Policies is a list of pod security policies which are available
	Policies map[string]extensions.PodSecurityPolicySpec `yaml:"policies"`
	// NamespaceMapping is a predefined list of namespace to policy mapping
	NamespaceMapping map[string]string `yaml:"namespace-mapping"`
}

// IsValid checks if the pod authorization config is valid
func (c *Config) IsValid() error {
	if len(c.Policies) == 0 {
		return errors.New("zero policies defined")
	}

	if c.Default == "" {
		return errors.New("no default security policy defined")
	}

	if _, found := c.Policies[c.Default]; !found {
		return errors.New("the default policy not found in policies")
	}

	if c.NamespaceMapping != nil {
		for namespace, name := range c.NamespaceMapping {
			if _, found := c.Policies[name]; !found {
				return fmt.Errorf("the mapping for namespace: '%q' policy: '%q' does not exist", namespace, name)
			}
		}
	}

	return nil
}

// defaultPolicy returns a predefined policy for a namespace
func (c *Config) defaultPolicy(namespace string) (string, bool) {
	if c.NamespaceMapping == nil {
		return "", false
	}
	name, found := c.NamespaceMapping[namespace]

	return name, found
}

// NewDefaultConfig returns a default configuration for the authorizer
func NewDefaultConfig() *Config {
	return &Config{
		Default:          "default",
		IgnoreNamespaces: []string{},
		NamespaceMapping: make(map[string]string, 0),
		Policies: map[string]extensions.PodSecurityPolicySpec{
			"default": {
				AllowedCapabilities:      []core.Capability{},
				DefaultAddCapabilities:   []core.Capability{},
				FSGroup:                  extensions.FSGroupStrategyOptions{Rule: extensions.FSGroupStrategyRunAsAny},
				RequiredDropCapabilities: []core.Capability{},
				RunAsUser: extensions.RunAsUserStrategyOptions{
					Rule:   extensions.RunAsUserStrategyMustRunAsNonRoot,
					Ranges: []extensions.UserIDRange{{Min: 1024, Max: 65535}},
				},
				SELinux:            extensions.SELinuxStrategyOptions{Rule: extensions.SELinuxStrategyRunAsAny},
				SupplementalGroups: extensions.SupplementalGroupsStrategyOptions{Rule: extensions.SupplementalGroupsStrategyRunAsAny},
				Volumes: []extensions.FSType{
					extensions.ConfigMap,
					extensions.EmptyDir,
					extensions.GitRepo,
					extensions.Projected,
					extensions.Secret,
				},
			},
			"privileged": {
				AllowedCapabilities:    []core.Capability{"*"},
				FSGroup:                extensions.FSGroupStrategyOptions{Rule: extensions.FSGroupStrategyRunAsAny},
				HostIPC:                true,
				HostNetwork:            true,
				HostPID:                true,
				HostPorts:              []extensions.HostPortRange{{Min: 1, Max: 65536}},
				Privileged:             true,
				ReadOnlyRootFilesystem: false,
				RunAsUser:              extensions.RunAsUserStrategyOptions{Rule: extensions.RunAsUserStrategyRunAsAny},
				SELinux:                extensions.SELinuxStrategyOptions{Rule: extensions.SELinuxStrategyRunAsAny},
				SupplementalGroups:     extensions.SupplementalGroupsStrategyOptions{Rule: extensions.SupplementalGroupsStrategyRunAsAny},
				Volumes:                []extensions.FSType{extensions.All},
			},
		},
	}
}
