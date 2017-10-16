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

import (
	"testing"

	"github.com/UKHomeOffice/policy-admission/pkg/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	core "k8s.io/kubernetes/pkg/api"
)

func TestNew(t *testing.T) {
	c, err := New(nil)
	assert.NotNil(t, c)
	assert.NoError(t, err)
}

func TestAuthorizer(t *testing.T) {
	checks := map[string]namespaceCheck{
		"check the namespace fails without any attributes": {
			Errors: field.ErrorList{
				{Field: "project", BadValue: "", Type: field.ErrorTypeInvalid, Detail: "required annotation missing"},
				{Field: "project", BadValue: "", Type: field.ErrorTypeInvalid, Detail: "required annotation empty"},
				{Field: "email", BadValue: "", Type: field.ErrorTypeInvalid, Detail: "required annotation missing"},
				{Field: "email", BadValue: "", Type: field.ErrorTypeInvalid, Detail: "required annotation empty"},
				{Field: "test", BadValue: "", Type: field.ErrorTypeInvalid, Detail: "required annotation missing"},
				{Field: "test", BadValue: "", Type: field.ErrorTypeInvalid, Detail: "required annotation empty"},
			},
		},
		"checking the attributes are working": {
			Annotations: map[string]string{
				"project": "test",
				"email":   "gambol99@gmail.com",
				"test":    "hello_world",
			},
		},
		"checking the required field is working": {
			Annotations: map[string]string{
				"project": "test",
				"test":    "hello_world",
			},
			Errors: field.ErrorList{
				{Field: "email", BadValue: "", Type: field.ErrorTypeInvalid, Detail: "required annotation missing"},
				{Field: "email", BadValue: "", Type: field.ErrorTypeInvalid, Detail: "required annotation empty"},
			},
		},
		"checking the require but empty is working": {
			Annotations: map[string]string{
				"project": "test",
				"email":   "",
				"test":    "hello_world",
			},
			Errors: field.ErrorList{
				{Field: "email", BadValue: "", Type: field.ErrorTypeInvalid, Detail: "required annotation empty"},
			},
		},
		"checking the validator is working": {
			Annotations: map[string]string{
				"project": "test",
				"email":   "test",
				"test":    "bad value",
			},
			Errors: field.ErrorList{
				{Field: "test", BadValue: "bad value", Type: field.ErrorTypeInvalid, Detail: "invalid value for annotation"},
			},
		},
	}
	newTestAuthorizer(t, nil).runChecks(t, checks)
}

type namespaceCheck struct {
	Annotations map[string]string
	Labels      map[string]string
	Errors      field.ErrorList
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

func (c *testAuthorizer) runChecks(t *testing.T, checks map[string]namespaceCheck) {
	for desc, check := range checks {
		namespace := newTestNamespace()
		if check.Annotations != nil {
			namespace.Annotations = check.Annotations
		}
		if check.Labels != nil {
			namespace.Labels = check.Labels
		}
		assert.Equal(t, check.Errors, c.svc.Admit(nil, nil, namespace), "case: '%s' result not as expected", desc)
	}
}

func newTestNamespace() *core.Namespace {
	return &core.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test",
			Annotations: make(map[string]string, 0),
			Labels:      make(map[string]string, 0),
		},
	}
}

func newTestConfig() *Config {
	return &Config{
		Attributes: []*Attribute{
			{
				Name:     "project",
				Type:     TypeAnnotation,
				Required: true,
			},
			{
				Name:     "email",
				Type:     TypeAnnotation,
				Required: true,
			},
			{
				Name:     "test",
				Type:     TypeAnnotation,
				Required: true,
				Validate: "^hello.*world$",
			},
			{
				Name:     "mylabel",
				Type:     TypeLabel,
				Validate: "^gambol99$",
			},
		},
	}
}
