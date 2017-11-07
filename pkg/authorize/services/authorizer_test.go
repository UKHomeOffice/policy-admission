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

package services

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

type serviceCheck struct {
	Errors    field.ErrorList
	Service   *core.Service
	Whitelist string
}

func TestDefaultConfig(t *testing.T) {
	assert.NotNil(t, NewDefaultConfig())
}

func TestNewAuthorizer(t *testing.T) {
	e, err := New(newTestConfig())
	assert.NotNil(t, e)
	assert.NoError(t, err)
}

func TestAuthorizer(t *testing.T) {
	checks := map[string]serviceCheck{
		"check a cluster ip service is allowed though": {
			Service: &core.Service{
				Spec: core.ServiceSpec{Type: core.ServiceTypeClusterIP},
			},
		},
		"check a nodeport service is allowed though": {
			Service: &core.Service{
				Spec: core.ServiceSpec{Type: core.ServiceTypeNodePort},
			},
		},
		"check a load balancer service is denied": {
			Service: &core.Service{
				Spec: core.ServiceSpec{Type: core.ServiceTypeLoadBalancer},
			},
			Errors: field.ErrorList{
				{
					Field:    "spec.type",
					BadValue: core.ServiceTypeLoadBalancer,
					Type:     field.ErrorTypeInvalid,
					Detail:   "service type denied by cluster policy",
				},
			},
		},
		"check the service is permitted with an namespace annotation": {
			Whitelist: "LoadBalancer",
			Service: &core.Service{
				Spec: core.ServiceSpec{Type: core.ServiceTypeLoadBalancer},
			},
		},
	}
	newTestAuthorizer(t, nil).runChecks(t, checks)
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

func (c *testAuthorizer) runChecks(t *testing.T, checks map[string]serviceCheck) {
	for desc, check := range checks {
		namespace := newTestNamespace()
		if check.Whitelist != "" {
			namespace.Annotations[Annotation] = check.Whitelist
		}

		client := fake.NewSimpleClientset()
		client.CoreV1().Namespaces().Create(namespace)
		mcache := cache.New(1*time.Minute, 1*time.Minute)

		assert.Equal(t, check.Errors, c.svc.Admit(client, mcache, check.Service), "case: '%s' result not as expected", desc)
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
	return NewDefaultConfig()
}
