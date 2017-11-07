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

package denyloadbalancers

import (
	"testing"

	"github.com/UKHomeOffice/policy-admission/pkg/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/validation/field"
	core "k8s.io/kubernetes/pkg/api"
)

type serviceCheck struct {
	Errors  field.ErrorList
	Service *core.Service
}

func TestDefaultConfig(t *testing.T) {
	assert.NotNil(t, NewDefaultConfig())
}

func TestNewDenyLoadbalancersAuthorizer(t *testing.T) {
	e, err := New(newTestConfig())
	assert.NotNil(t, e)
	assert.NoError(t, err)
}

func TestDenyLoadbalancerAuthorizer(t *testing.T) {
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
					Field:    "service",
					BadValue: core.ServiceTypeLoadBalancer,
					Type:     field.ErrorTypeInvalid,
					Detail:   "loadbalancer services are denied by policy",
				},
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
		assert.Equal(t, check.Errors, c.svc.Admit(nil, nil, check.Service), "case: '%s' result not as expected", desc)
	}
}

func newTestConfig() *Config {
	return NewDefaultConfig()
}
