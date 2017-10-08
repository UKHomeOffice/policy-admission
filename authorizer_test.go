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
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	core "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

type podCheck struct {
	context *core.PodSecurityContext
	pod     *core.Pod
	errors  field.ErrorList
	ok      bool
	policy  string
}

func TestNewEnforcer(t *testing.T) {
	p, err := newPodAuthorizer(newFakePodAuthorizerConfig())
	assert.NotNil(t, p)
	assert.NoError(t, err)
	assert.Equal(t, len(p.providers), 2)
}

func TestNewEnforcerWithConfig(t *testing.T) {
	config, err := createPodAuthorizorConfig("./tests/config.yml")
	require.NotNil(t, config)
	require.NoError(t, err)
	p, err := newPodAuthorizer(config)
	assert.NoError(t, err)
	assert.NotNil(t, p)
}

func TestProviderNotFound(t *testing.T) {
	checks := map[string]podCheck{
		"check we get a provider not found error": {
			context: &core.PodSecurityContext{},
			policy:  "no_there",
			errors: field.ErrorList{
				{
					Detail: "no such policy found",
					Type:   field.ErrorTypeNotFound,
				},
			},
		},
	}
	checkAuthorizer(t, checks)
}

func TestHostNetworkPodChecks(t *testing.T) {
	checks := map[string]podCheck{
		"checking the host network is denied in default": {
			context: &core.PodSecurityContext{HostNetwork: true},
			policy:  "default",
			errors: field.ErrorList{
				{
					BadValue: true,
					Detail:   "Host network is not allowed to be used",
					Field:    "[][].hostNetwork",
					Type:     field.ErrorTypeInvalid,
				},
			},
		},
		"checking the host network is permitted with privileged": {
			context: &core.PodSecurityContext{HostNetwork: true},
			policy:  "privileged",
			ok:      true,
		},
		"checking the default policy is working": {
			context: &core.PodSecurityContext{HostNetwork: true},
		},
	}
	checkAuthorizer(t, checks)
}

func TestPodVolumeChecks(t *testing.T) {
	hostPathPod := newDefaultPod()
	hostPathPod.Spec.Volumes = []core.Volume{
		{
			Name:         "root",
			VolumeSource: core.VolumeSource{HostPath: &core.HostPathVolumeSource{Path: "/"}},
		},
	}

	secretPod := newDefaultPod()
	secretPod.Spec.Volumes = []core.Volume{
		{
			Name:         "root",
			VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: "test"}},
		},
	}

	checks := map[string]podCheck{
		"check the pod is denied host path volume on default": {
			pod: hostPathPod,
			errors: field.ErrorList{
				{
					BadValue: "hostPath",
					Detail:   "hostPath volumes are not allowed to be used",
					Field:    "spec.volumes[0]",
					Type:     field.ErrorTypeInvalid,
				},
			},
		},
		"check the pod is permitted host path volume on privileged": {
			pod:    hostPathPod,
			policy: "privileged",
			ok:     true,
		},
		"check the volume type secret is enabled": {
			pod: secretPod,
			ok:  true,
		},
	}
	checkAuthorizer(t, checks)
}

func TestPodPrivilegedChecks(t *testing.T) {
	pod := newDefaultPod()
	priv := true
	pod.Spec.Containers = []core.Container{
		{
			Name:  "test",
			Image: "nginx",
			SecurityContext: &core.SecurityContext{
				Privileged: &priv,
			},
		},
	}
	checks := map[string]podCheck{
		"checking the privileged container is denied on default policy": {
			pod: pod,
		},
		"checking the privileged container is allowed via privileged policy": {
			pod:    pod,
			policy: "privileged",
			ok:     true,
		},
	}
	checkAuthorizer(t, checks)
}

func newFakePodAuthorizerConfig() *podAuthorizerConfig {
	return &podAuthorizerConfig{
		Default:          "default",
		IgnoreNamespaces: []string{"ignored"},
		NamespaceMapping: map[string]string{"kube-system": "privileged"},
		Policies: map[string]extensions.PodSecurityPolicySpec{
			"default": {
				AllowPrivilegeEscalation: true,
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
			"privileged": {
				AllowPrivilegeEscalation: true,
				AllowedCapabilities:      []core.Capability{"*"},
				FSGroup:                  extensions.FSGroupStrategyOptions{Rule: extensions.FSGroupStrategyRunAsAny},
				HostIPC:                  true,
				HostNetwork:              true,
				HostPID:                  true,
				HostPorts:                []extensions.HostPortRange{{Min: 1, Max: 65536}},
				Privileged:               true,
				ReadOnlyRootFilesystem:   false,
				RunAsUser:                extensions.RunAsUserStrategyOptions{Rule: extensions.RunAsUserStrategyRunAsAny},
				SELinux:                  extensions.SELinuxStrategyOptions{Rule: extensions.SELinuxStrategyRunAsAny},
				SupplementalGroups:       extensions.SupplementalGroupsStrategyOptions{Rule: extensions.SupplementalGroupsStrategyRunAsAny},
				Volumes:                  []extensions.FSType{extensions.All},
			},
		},
	}
}

func newDefaultPod() *core.Pod {
	var notPriv bool = false
	return &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "my-pod",
			Namespace:   "my-namespace",
			Annotations: map[string]string{},
		},
		Spec: core.PodSpec{
			SecurityContext: &core.PodSecurityContext{},
			Containers: []core.Container{
				{
					Name: "test-pod",
					SecurityContext: &core.SecurityContext{
						Privileged: &notPriv,
					},
				},
			},
		},
	}
}

func checkAuthorizer(t *testing.T, checks map[string]podCheck) {
	p, err := newPodAuthorizer(newFakePodAuthorizerConfig())
	require.NoError(t, err)

	for name, check := range checks {
		pod := check.pod
		if pod == nil {
			pod = newDefaultPod()
		}
		if check.context != nil {
			pod.Spec.SecurityContext = check.context
		}

		ok, violations := p.authorize(check.policy, pod)
		assert.Equal(t, check.ok, ok, "case: '%s', expected: %t, got: %t", name, check.ok, ok)
		if len(check.errors) > 0 {
			assert.Equal(t, check.errors, violations, "case: '%s', violation mismatched", name)
		}
	}
}
