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

package domains

import (
	"context"
	"testing"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/fake"
)

type domainsCheck struct {
	Errors    field.ErrorList
	Hostname  string
	Whitelist string
}

func TestDefaultConfig(t *testing.T) {
	assert.NotNil(t, NewDefaultConfig())
}

func TestNewDomainsAuthorizer(t *testing.T) {
	e, err := New(newTestConfig())
	assert.NotNil(t, e)
	assert.NoError(t, err)
}

func TestDomainsAuthorizer(t *testing.T) {
	checks := map[string]domainsCheck{
		"check the ingress is denied when no annotation": {
			Hostname: "test.domain.com",
			Errors: field.ErrorList{
				{
					Field:    "namespace.annotations[policy-admission.acp.homeoffice.gov.uk/domains]",
					BadValue: "",
					Type:     field.ErrorTypeInvalid,
					Detail:   "no whitelist annotation",
				},
			},
		},
		"check the ingress allowed when annotated": {
			Hostname:  "test.domain.com",
			Whitelist: "test.domain.com",
		},
		"check the ingress allowed with multi host are specified": {
			Hostname:  "test.domain.com",
			Whitelist: "bad.domain.com,test.domain.com",
		},
		"check the ingress allowed with whitespace": {
			Hostname:  "test.domain.com",
			Whitelist: " bad.domain.com,  test.domain.com",
		},
		"check the ingress allowed weird whitespace": {
			Hostname:  "test.domain.com",
			Whitelist: " bad.domain.com,test.domain.com",
		},
		"check the ingress allowed when using a wildcard": {
			Hostname:  "test.domain.com",
			Whitelist: "*.domain.com",
		},
		"check the ingress allow with multiple whielists": {
			Hostname:  "test.another.example.com",
			Whitelist: "*.domain.com,*.another.example.com",
		},
		"check the ingress denied for a subdomain": {
			Hostname:  "bad.test.domain.com",
			Whitelist: "*.domain.com",
			Errors: field.ErrorList{
				{
					Field:    "spec.rules[0].host",
					BadValue: "bad.test.domain.com",
					Type:     field.ErrorTypeInvalid,
					Detail:   "host is not permitted by namespace policy",
				},
			},
		},
		"check it a single wildcard doesnt cover everything": {
			Hostname:  "bad.test.domain.com",
			Whitelist: "*",
			Errors: field.ErrorList{
				{
					Field:    "spec.rules[0].host",
					BadValue: "bad.test.domain.com",
					Type:     field.ErrorTypeInvalid,
					Detail:   "host is not permitted by namespace policy",
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

func (c *testAuthorizer) runChecks(t *testing.T, checks map[string]domainsCheck) {
	for desc, check := range checks {
		ctx := newTestContext()
		namespace := newTestNamespace()
		if check.Whitelist != "" {
			namespace.Annotations[ctx.Annotation(Name)] = check.Whitelist
		}
		ctx.Client.CoreV1().Namespaces().Create(namespace)

		ctx.Object = newTestIngress(check.Hostname)

		assert.Equal(t, check.Errors, c.svc.Admit(context.TODO(), ctx), "case: '%s' result not as expected", desc)
	}
}

func newTestIngress(hostname string) *networkingv1beta1.Ingress {
	if hostname == "" {
		hostname = "test.test.svc.cluster.local"
	}
	return &networkingv1beta1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "test"},
		Spec: networkingv1beta1.IngressSpec{
			TLS: []networkingv1beta1.IngressTLS{
				{Hosts: []string{hostname}, SecretName: "tls"},
			},
			Rules: []networkingv1beta1.IngressRule{{Host: hostname}},
		},
		Status: networkingv1beta1.IngressStatus{},
	}
}

func newTestContext() *api.Context {
	return &api.Context{
		Cache:  cache.New(1*time.Minute, 1*time.Minute),
		Client: fake.NewSimpleClientset(),
		Prefix: "policy-admission.acp.homeoffice.gov.uk",
	}
}

func newTestNamespace() *core.Namespace {
	return &core.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test",
			Annotations: make(map[string]string, 0),
		},
	}
}

func newTestConfig() *Config {
	return &Config{}
}
