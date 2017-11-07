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
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/fake"
	core "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

var (
	isTrue  = true
	isFalse = false
)

type podCheck struct {
	Annotation string
	Context    *core.PodSecurityContext
	Errors     field.ErrorList
	Namespace  *v1.Namespace
	Pod        *core.Pod
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
			Context:    &core.PodSecurityContext{},
			Annotation: "not_there",
			Errors: field.ErrorList{
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

func TestAllowCaps(t *testing.T) {
	pod := newTestPod()
	pod.Spec.Containers = []core.Container{
		{
			Name:  "test-1",
			Image: "nginx",
			SecurityContext: &core.SecurityContext{
				Capabilities: &core.Capabilities{
					Add: []core.Capability{"NET_ADMIN"},
				},
				RunAsNonRoot: &isTrue,
			},
		},
	}
	checks := map[string]podCheck{
		"checking the pods with no non-root fail on default policy": {
			Annotation: "default",
			Pod:        pod,
			Errors: field.ErrorList{
				{
					BadValue: "NET_ADMIN",
					Detail:   "capability may not be added",
					Field:    "capabilities.add",
					Type:     field.ErrorTypeInvalid,
				},
			},
		},
	}
	checkAuthorizer(t, checks)
}

func TestRunNonRootChecks(t *testing.T) {
	nonroot := newTestPod()
	nonroot.Spec.Containers = []core.Container{
		{
			Name:            "test-1",
			Image:           "nginx",
			SecurityContext: &core.SecurityContext{},
		},
	}
	root := newTestPod()
	root.Spec.Containers = []core.Container{
		{
			Name:            "test-1",
			Image:           "nginx",
			SecurityContext: &core.SecurityContext{RunAsNonRoot: &isFalse},
		},
	}
	unset := newTestPod()
	unset.Spec.Containers[0].SecurityContext.RunAsNonRoot = nil

	checks := map[string]podCheck{
		"checking the pods with no non-root fail on default policy": {
			Pod: nonroot,
			Errors: field.ErrorList{
				{
					BadValue: false,
					Detail:   "RunAsNonRoot must be true for container test-1",
					Field:    "securityContext.runAsNonRoot",
					Type:     field.ErrorTypeInvalid,
				},
			},
		},
		"check running as root is ok for privileged containers": {
			Pod:        root,
			Annotation: "privileged",
		},
		"check running as root is fine when not defined": {
			Pod:        unset,
			Annotation: "privileged",
		},
	}
	checkAuthorizer(t, checks)
}

func TestHostNetworkPodChecks(t *testing.T) {
	checks := map[string]podCheck{
		"checking the host network is denied in default": {
			Context: &core.PodSecurityContext{HostNetwork: true, RunAsNonRoot: &isTrue},
			Errors: field.ErrorList{
				{
					BadValue: true,
					Detail:   "Host network is not allowed to be used",
					Field:    "spec.securityContext.hostNetwork",
					Type:     field.ErrorTypeInvalid,
				},
			},
		},
		"checking the host network is permitted with privileged": {
			Annotation: "privileged",
			Context:    &core.PodSecurityContext{HostNetwork: true, RunAsNonRoot: &isTrue},
		},
	}
	checkAuthorizer(t, checks)
}

func TestPodVolumeChecks(t *testing.T) {
	hostPathPod := newTestPod()
	hostPathPod.Spec.Volumes = []core.Volume{
		{
			Name:         "root",
			VolumeSource: core.VolumeSource{HostPath: &core.HostPathVolumeSource{Path: "/"}},
		},
	}

	secretPod := newTestPod()
	secretPod.Spec.Volumes = []core.Volume{
		{
			Name:         "root",
			VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: "test"}},
		},
	}

	checks := map[string]podCheck{
		"check the pod is denied host path volume on default": {
			Pod: hostPathPod,
			Errors: field.ErrorList{
				{
					BadValue: "hostPath",
					Detail:   "hostPath volumes are not allowed to be used",
					Field:    "spec.volumes[0]",
					Type:     field.ErrorTypeInvalid,
				},
			},
		},
		"check the pod is permitted host path volume on privileged": {
			Pod:        hostPathPod,
			Annotation: "privileged",
		},
		"check the volume type secret is enabled": {
			Pod: secretPod,
		},
	}
	checkAuthorizer(t, checks)
}

func TestPodPrivilegedChecks(t *testing.T) {
	pod := newTestPod()
	pod.Spec.Containers = []core.Container{
		{
			Name:            "test",
			Image:           "nginx",
			SecurityContext: &core.SecurityContext{Privileged: &isTrue, RunAsNonRoot: &isTrue},
		},
	}
	checks := map[string]podCheck{
		"checking the privileged container is denied on default policy": {
			Pod: pod,
			Errors: field.ErrorList{
				{
					BadValue: true,
					Detail:   "Privileged containers are not allowed",
					Field:    "spec.containers[0].securityContext.privileged",
					Type:     field.ErrorTypeInvalid,
				},
			},
		},
		"checking the privileged container is allowed via privileged policy": {
			Annotation: "privileged",
			Pod:        pod,
		},
	}
	checkAuthorizer(t, checks)
}

func checkAuthorizer(t *testing.T, checks map[string]podCheck) {
	p, err := New(newTestConfig())
	require.NoError(t, err)

	for name, check := range checks {
		pod := check.Pod
		if pod == nil {
			pod = newTestPod()
		}
		namespace := check.Namespace
		if namespace == nil {
			namespace = newTestNamespace()
		}
		if check.Annotation != "" {
			namespace.Annotations[Annotation] = check.Annotation
		}
		client := fake.NewSimpleClientset()
		client.CoreV1().Namespaces().Create(namespace)
		mcache := cache.New(1*time.Minute, 1*time.Minute)

		if check.Context != nil {
			pod.Spec.SecurityContext = check.Context
		}
		assert.Equal(t, check.Errors, p.Admit(client, mcache, pod), "case: '%s', violation mismatched", name)
	}
}

func newTestPod() *core.Pod {
	isTrue := true
	return &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "pod",
			Namespace:   "test",
			Annotations: map[string]string{},
		},
		Spec: core.PodSpec{
			Containers: []core.Container{
				{
					Name:            "test-pod",
					SecurityContext: &core.SecurityContext{RunAsNonRoot: &isTrue},
				},
			},
		},
	}
}

func newTestNamespace() *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test",
			Annotations: make(map[string]string, 0),
		},
	}
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
					Rule: extensions.RunAsUserStrategyMustRunAsNonRoot,
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
