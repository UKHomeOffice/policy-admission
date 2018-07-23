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
	"context"
	"encoding/json"
	"io/ioutil"
	"testing"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

func TestNew(t *testing.T) {
	s, err := New(nil)
	assert.NotNil(t, s)
	assert.NoError(t, err)
}

func TestNewFileConfig(t *testing.T) {
	s, err := NewFromFile("./features/config.yml")
	assert.NotNil(t, s)
	assert.NoError(t, err)
}

func TestDefaultConfig(t *testing.T) {
	assert.NotNil(t, NewDefaultConfig())
}

func TestScriptTimeout(t *testing.T) {
	checks := map[string]check{
		"ensure the script is timed out": {
			Object: &core.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind: "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
			},
			Config: &Config{
				Script:  `while (true) { }`,
				Timeout: 50 * time.Millisecond,
			},
			Errors: field.ErrorList{
				{
					Type:   field.ErrorTypeInternal,
					Field:  "[]",
					Detail: "operation timed out",
				},
			},
		},
	}
	newTestAuthorizer(t, nil).runChecks(t, checks)
}

func TestScriptAuthorizer(t *testing.T) {
	checks := map[string]check{
		"checking the certificate is permitted": {
			ScriptFile: "features/cert-manager-certificate.js",
			ObjectFile: "features/cert-manager-certificate-ok.json",
		},
		"checking the certificate is denied on a bad common name": {
			ScriptFile: "features/cert-manager-certificate.js",
			ObjectFile: "features/cert-manager-certificate-bad-cn.json",
			Errors: field.ErrorList{
				{
					Type:     field.ErrorTypeInvalid,
					Field:    "spec.commonName",
					BadValue: "this.is.bad",
					Detail:   "certificate common name: this.is.bad does not comply with cluster policy",
				},
			},
		},
		"checking the certificate is denied on a bad dnsName": {
			ScriptFile: "features/cert-manager-certificate.js",
			ObjectFile: "features/cert-manager-certificate-bad-dnsname.json",
			Errors: field.ErrorList{
				{
					Type:     field.ErrorTypeInvalid,
					Field:    "spec.dnsNames[1]",
					BadValue: "bas.host",
					Detail:   "bas.host is denied by cluster policy, being outside your namespace",
				},
			},
		},
		"checking the certificate is denied on a bad namespace": {
			ScriptFile: "features/cert-manager-certificate.js",
			ObjectFile: "features/cert-manager-certificate-bad-namespace.json",
			Errors: field.ErrorList{
				{
					Type:     field.ErrorTypeInvalid,
					Field:    "spec.dnsNames[0]",
					BadValue: "test.default.svc.cluster.local",
					Detail:   "test.default.svc.cluster.local is denied by cluster policy, being outside your namespace",
				},
			},
		},
		"check the action is deny when a kind is pod": {
			Config: &Config{
				Script: `
			if (object.kind == "Pod") {
				deny("kind", "denied by security policy", object.kind)
			}
			`,
			},
			Object: &core.Pod{
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
			Object: &core.Pod{
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
		"checking the dns is ok": {
			ScriptFile: "features/cert-manager-ingress-dns01.js",
			ObjectFile: "features/cert-manager-ingress-dns01-ok.json",
		},
		"checking the dns is denied": {
			ScriptFile: "features/cert-manager-ingress-dns01.js",
			ObjectFile: "features/cert-manager-ingress-dns01-bad.json",
			Errors: field.ErrorList{
				{
					Type:     field.ErrorTypeInvalid,
					BadValue: "site.bad_domains.com",
					Field:    "spec.rules[0].host",
					Detail:   "the hostname is not permitted by policy",
				},
			},
		},
		"checking the ingress scripts find the errors": {
			ScriptFile: "features/deny_ingress_annotations.js",
			ObjectFile: "features/ingress_bad.json",
			Errors: field.ErrorList{
				{
					Type:     field.ErrorTypeInvalid,
					BadValue: "th_;_is_abad_url//\\",
					Field:    "metadata.annotations[ingress.kubernetes.io/app-root]",
					Detail:   "invalid user input, should match: /^((https?)://)?([w|W]{3}.)+[a-zA-Z0-9-.]{3,}.[a-zA-Z]{2,}(.[a-zA-Z]{2,})?$/",
				},
				{
					Type:     field.ErrorTypeInvalid,
					BadValue: "4MM",
					Field:    "metadata.annotations[ingress.kubernetes.io/client-body-buffer-size]",
					Detail:   "invalid user input, should match: /^[0-9]*[mkg]$/",
				},
				{
					Type:     field.ErrorTypeInvalid,
					BadValue: "4k0",
					Field:    "metadata.annotations[ingress.kubernetes.io/limit-connections]",
					Detail:   "invalid user input, should match: /^[0-9]*$/",
				},
				{
					Type:     field.ErrorTypeInvalid,
					BadValue: "truedd",
					Field:    "metadata.annotations[ingress.kubernetes.io/secure-backends]",
					Detail:   "invalid user input, should match: /^(true|false)$/",
				},
			},
		},
		"checking the ingress passes the validation": {
			ScriptFile: "features/deny_ingress_annotations.js",
			ObjectFile: "features/ingress_ok.json",
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
	cx := newTestContext()
	cx.Client.CoreV1().Namespaces().Create(&core.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test",
			Annotations: make(map[string]string, 0),
		},
	})

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

			object := &unstructured.Unstructured{}
			if err = json.Unmarshal(encoded, object); err != nil {
				require.NoError(t, err, "case: %s, unable to unmarshal, error: %s", desc, err)
			}
			check.Object = object
		}
		cx.Object = check.Object

		assert.Equal(t, check.Errors, c.svc.Admit(context.TODO(), cx), "case: '%s' result not as expected", desc)
	}
}

func newTestContext() *api.Context {
	return &api.Context{
		Cache:  cache.New(1*time.Minute, 1*time.Minute),
		Client: fake.NewSimpleClientset(),
		Prefix: "policy-admission.acp.homeoffice.gov.uk",
	}
}

func newTestConfig() *Config {
	return &Config{}
}
