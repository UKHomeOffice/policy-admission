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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	core "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

func TestNewEnforcer(t *testing.T) {
	p, err := newPodAuthorizer(newFakePodAuthorizerConfig())
	assert.NotNil(t, p)
	assert.NoError(t, err)
	assert.Equal(t, len(p.providers), 2)
}

func newFakePodAuthorizerConfig() *podAuthorizerConfig {
	return &podAuthorizerConfig{
		DefaultPolicy:    "default",
		IgnoreNamespaces: []string{"kube-system"},
		Policies: map[string]*extensions.PodSecurityPolicy{
			"default": &extensions.PodSecurityPolicy{
				Spec: extensions.PodSecurityPolicySpec{
					AllowedCapabilities:      []core.Capability{},
					DefaultAddCapabilities:   []core.Capability{},
					FSGroup:                  extensions.FSGroupStrategyOptions{Rule: extensions.FSGroupStrategyRunAsAny},
					RequiredDropCapabilities: []core.Capability{},
					RunAsUser: extensions.RunAsUserStrategyOptions{
						Rule:   extensions.RunAsUserStrategyMustRunAsNonRoot,
						Ranges: []extensions.UserIDRange{{Min: 2, Max: 1024}},
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
			},
			"privileged": &extensions.PodSecurityPolicy{
				Spec: extensions.PodSecurityPolicySpec{
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
		},
	}
}
