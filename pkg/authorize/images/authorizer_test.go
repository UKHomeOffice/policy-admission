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

import (
	"testing"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/fake"
	core "k8s.io/kubernetes/pkg/api"
)

func TestNew(t *testing.T) {
	c, err := New(newTestConfig())
	assert.NotNil(t, c)
	assert.NoError(t, err)
}

func TestNewDefaultConfig(t *testing.T) {
	assert.NotNil(t, NewDefaultConfig())
}

func TestAuthorizer(t *testing.T) {
	checks := map[string]imageCheck{
		"check that the pod is allow through with no default or annotation policy": {},
		"check the namespace annotation blocks the image": {
			Whitelist: "docker.io/.*",
			Image:     "testimage:latest",
			Errors: field.ErrorList{
				{
					Field:    "testimage:latest",
					BadValue: "",
					Type:     field.ErrorTypeForbidden,
					Detail:   "image denied by policy",
				},
			},
		},
		"checking the annonation permits the image": {
			Whitelist: "testimage:latest",
			Image:     "testimage:latest",
		},
		"check that multiple whitelists are processed": {
			Whitelist: "another_image, testimage:latest",
			Image:     "testimage:latest",
		},
		"check for more complex regexes are oke": {
			Whitelist: "^docker.io/.*$, ^.*:lates[tT]$",
			Image:     "testimage:latest",
		},
	}
	newTestAuthorizer(t, nil).runChecks(t, checks)
}

func TestDefaultPolicy(t *testing.T) {
	config := newTestConfig()
	config.ImagePolicies = []string{"^docker.io/.*:.*$"}
	checks := map[string]imageCheck{
		"check the default policies are being applied and image allowed": {
			Image: "docker.io/test:latest",
		},
		"check the image is being denied by the default policy": {
			Image: "should_not_work",
			Errors: field.ErrorList{
				{
					Field:    "should_not_work",
					BadValue: "",
					Type:     field.ErrorTypeForbidden,
					Detail:   "image denied by policy",
				},
			},
		},
		"check the namespace annotation adds to the whitelist": {
			Image:     "should_not_work",
			Whitelist: "should.*$",
		},
	}
	newTestAuthorizer(t, config).runChecks(t, checks)
}

type imageCheck struct {
	Errors    field.ErrorList
	Image     string
	Pod       *core.Pod
	Whitelist string
}

type testAuthorizer struct {
	config *Config
	svc    api.Authorize
}

func newTestAuthorizer(t *testing.T, config *Config) *testAuthorizer {
	if config == nil {
		config = newTestConfig()
	}
	c, err := New(config)
	require.NoError(t, err)

	return &testAuthorizer{config: config, svc: c}
}

func (c *testAuthorizer) runChecks(t *testing.T, checks map[string]imageCheck) {
	for desc, check := range checks {
		namespace := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test"}}
		if check.Whitelist != "" {
			namespace.Annotations = map[string]string{Annotation: check.Whitelist}
		}
		pod := check.Pod
		if pod == nil {
			pod = newDefaultPod()
		}
		image := check.Image
		if image != "" {
			pod.Spec.Containers[0].Image = image
		}
		client := fake.NewSimpleClientset()
		client.CoreV1().Namespaces().Create(namespace)
		mcache := cache.New(1*time.Minute, 1*time.Minute)

		assert.Equal(t, check.Errors, c.svc.Admit(client, mcache, pod), "case: '%s' result not as expected", desc)
	}
}

func newDefaultPod() *core.Pod {
	return &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-",
			Namespace: "test",
		},
		Spec: core.PodSpec{
			Containers: []core.Container{
				{
					Name:  "nginx-",
					Image: "nginx:latest",
				},
			},
		},
	}
}

func newTestConfig() *Config {
	return &Config{
		IgnoreNamespaces: []string{"kube-system"},
	}
}
