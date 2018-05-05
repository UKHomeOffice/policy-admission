/*
Copyright 2018 Home Office All rights reserved.

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

package scripts

import (
	"encoding/json"
	"io/ioutil"
	"testing"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/fake"
)

type testAuthorizer struct {
	config *Config
	svc    api.Authorize
}

type check struct {
	Config     *Config
	Errors     field.ErrorList
	Object     metav1.Object
	ObjectFile string
	ScriptFile string
}

func TestDefaultConfig(t *testing.T) {
	assert.NotNil(t, NewDefaultConfig())
}

func TestScriptAuthorizer(t *testing.T) {
	checks := map[string]check{
		"check the action is deny when a kind is pod": {
			Config: &Config{
				Script: `
if (object.kind == "Pod") {
	deny("kind", "denied by security policy", object.kind)
}
`,
			},
			Object: &v1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind: "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
			},
			Errors: field.ErrorList{
				{
					Type:     field.ErrorTypeInvalid,
					Field:    "kind",
					BadValue: "Pod",
					Detail:   "denied by security policy",
				},
			},
		},
		"check the action is deny on a annotation": {
			Config: &Config{
				Script: `
if (object.kind == "Pod") {
	v = object.metadata.annotations["something"]
	if (v != "") {
		deny("metadata.annotations[something]", "no permitted", v)
	}
}
`,
			},
			Object: &v1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind: "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
					Annotations: map[string]string{
						"something": "hello",
					},
				},
			},
			Errors: field.ErrorList{
				{
					Type:     field.ErrorTypeInvalid,
					Field:    "metadata.annotations[something]",
					BadValue: "hello",
					Detail:   "no permitted",
				},
			},
		},
		"checking the deployment is allowed with bundle": {
			ScriptFile: "features/deny_no_bundle.js",
			ObjectFile: "features/deployment_with_bundle.json",
		},
		"checking the deployment is denied without bundle": {
			ScriptFile: "features/deny_no_bundle.js",
			ObjectFile: "features/deployment_without_bundle.json",
			Errors: field.ErrorList{
				{
					Type:     field.ErrorTypeInvalid,
					BadValue: "",
					Field:    "spec.initContainers[0].volumeMounts",
					Detail:   "cfssl-sidekick container needs to mount configmap: bundle in /etc/ssl/certs",
				},
			},
		},
	}
	newTestAuthorizer(t, nil).runChecks(t, checks)
}

func newTestAuthorizer(t *testing.T, config *Config) *testAuthorizer {
	if config == nil {
		config = newTestConfig()
	}
	c, err := New(config)
	require.NoError(t, err)

	return &testAuthorizer{config: config, svc: c}
}

func (c *testAuthorizer) runChecks(t *testing.T, checks map[string]check) {
	client := fake.NewSimpleClientset()
	client.CoreV1().Namespaces().Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test",
			Annotations: make(map[string]string, 0),
		},
	})
	mcache := cache.New(1*time.Minute, 1*time.Minute)

	for desc, check := range checks {
		s := c.svc.(*authorizer)

		if check.ScriptFile != "" {
			content, err := ioutil.ReadFile(check.ScriptFile)
			require.NoError(t, err, "case: %s, unable to read in request file, error: %s", desc, err)
			s.config.Script = string(content)
		} else {
			s.config = check.Config
		}

		if check.ObjectFile != "" {
			encoded, err := ioutil.ReadFile(check.ObjectFile)
			require.NoError(t, err, "case: %s, unable to read in script file, error: %s", desc, err)

			object := &extensions.Deployment{}
			if err = json.Unmarshal(encoded, object); err != nil {
				require.NoError(t, err, "case: %s, unable to unmarshal, error: %s", desc, err)
			}
			check.Object = object
		}

		assert.Equal(t, check.Errors, c.svc.Admit(client, mcache, check.Object), "case: '%s' result not as expected", desc)
	}
}

func newTestConfig() *Config {
	return &Config{}
}
