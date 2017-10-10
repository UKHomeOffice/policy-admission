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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	core "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

type podCheck struct {
	context   *core.PodSecurityContext
	errors    field.ErrorList
	namespace *v1.Namespace
	ok        bool
	pod       *core.Pod
	policy    string
}

func TestNew(t *testing.T) {
	p, err := New(newTestConfig())
	assert.NotNil(t, p)
	assert.NoError(t, err)
}

func TestNewFromFile(t *testing.T) {
	c, err := NewFromFile("./config_test.yml")
	assert.NoError(t, err)
	assert.NotNil(t, c)
}

func TestProviderNotFound(t *testing.T) {
	checks := map[string]podCheck{
		"check we get a provider not found error": {
			context: &core.PodSecurityContext{},
			policy:  "not_there",
			errors: field.ErrorList{
				{
					BadValue: "not_there",
					Detail:   "policy does not exist",
					Field:    "policy",
					Type:     field.ErrorTypeInvalid,
				},
			},
		},
	}
	checkAuthorizer(t, checks)
}

/*
func TestRunNonRootChecks(t *testing.T) {
	pod := newDefaultPod()
	pod.Spec.Containers = []core.Container{
		{
			Name:            "test-1",
			Image:           "nginx",
			SecurityContext: &core.SecurityContext{},
		},
	}

	checks := map[string]podCheck{
		"checking the pods with no non-root fail on default policy": {
			pod:    pod,
			policy: "default",
			errors: field.ErrorList{},
		},
	}
	checkAuthorizer(t, checks)
}
*/

func TestHostNetworkPodChecks(t *testing.T) {
	checks := map[string]podCheck{
		"checking the host network is denied in default": {
			context: &core.PodSecurityContext{HostNetwork: true},
			errors: field.ErrorList{
				{
					BadValue: true,
					Detail:   "Host network is not allowed to be used",
					Field:    "spec.securityContext.hostNetwork",
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
			Name:            "test",
			Image:           "nginx",
			SecurityContext: &core.SecurityContext{Privileged: &priv},
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

func newTestConfig() *Config {
	return &Config{
		Default:          "default",
		IgnoreNamespaces: []string{"ignored"},
		NamespaceMapping: map[string]string{"kube-system": "privileged"},
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

func newDefaultPod() *core.Pod {
	return &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "my-pod",
			Namespace:   "my-namespace",
			Annotations: map[string]string{},
		},
		Spec: core.PodSpec{
			Containers: []core.Container{
				{
					Name:            "test-pod",
					SecurityContext: &core.SecurityContext{},
				},
			},
		},
	}
}

func checkAuthorizer(t *testing.T, checks map[string]podCheck) {
	p, err := New(newTestConfig())
	require.NoError(t, err)

	for name, check := range checks {
		pod := check.pod
		if pod == nil {
			pod = newDefaultPod()
		}
		namespace := check.namespace
		if namespace == nil {
			namespace = &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test",
					Annotations: make(map[string]string, 0),
				},
			}
		}
		if check.policy != "" {
			namespace.Annotations[Annotation] = check.policy
		}

		if check.context != nil {
			pod.Spec.SecurityContext = check.context
		}

		violations := p.Admit(nil, namespace, pod)
		ok := len(violations) == 0
		assert.Equal(t, check.ok, ok, "case: '%s', expected: %t, got: %t", name, check.ok, ok)
		if len(check.errors) > 0 {
			assert.Equal(t, check.errors, violations, "case: '%s', violation mismatched", name)
		}
	}
}
