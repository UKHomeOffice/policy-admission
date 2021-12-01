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

package tolerations

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/fake"
)

type tolerationCheck struct {
	Config         *Config
	Errors         field.ErrorList
	Namespace      *core.Namespace
	Pod            *core.Pod
	PodTolerations []core.Toleration
	Whitelist      []core.Toleration
}

func TestDefaultConfig(t *testing.T) {
	assert.NotNil(t, NewDefaultConfig())
}

func TestNewTolerationAuthorizer(t *testing.T) {
	e, err := New(newTestConfig())
	assert.NotNil(t, e)
	assert.NoError(t, err)
}

func TestTolerationAuthorizer(t *testing.T) {
	checks := map[string]tolerationCheck{
		"check we permitted though when our namespace does not have a whitelist": {
			Namespace: newTestNamespace(),
		},
		"check the pod is refused when whitelist denies": {
			Whitelist: []core.Toleration{
				{
					Key:      "dedicated",
					Operator: core.TolerationOpEqual,
					Value:    "compute",
					Effect:   core.TaintEffectNoSchedule,
				},
			},
			PodTolerations: []core.Toleration{
				{
					Key:      "dedicated",
					Operator: core.TolerationOpEqual,
					Value:    "not_permitted",
					Effect:   core.TaintEffectNoSchedule,
				},
			},
			Errors: field.ErrorList{
				{
					Field:    "spec.tolerations[0]",
					BadValue: "dedicated=not_permitted:NoSchedule",
					Type:     field.ErrorTypeInvalid,
					Detail:   "toleration denied by whitelist",
				},
			},
		},
		"check the order of the whitelist does not matter": {
			Whitelist: []core.Toleration{
				{
					Key:      "dedicated",
					Operator: core.TolerationOpEqual,
					Value:    "compute",
					Effect:   core.TaintEffectNoSchedule,
				},
				{
					Key:      "dedicated",
					Operator: core.TolerationOpEqual,
					Value:    "ingress",
					Effect:   core.TaintEffectNoSchedule,
				},
			},
			PodTolerations: []core.Toleration{
				{
					Key:      "dedicated",
					Operator: core.TolerationOpEqual,
					Value:    "ingress",
					Effect:   core.TaintEffectNoSchedule,
				},
			},
		},
		"check that a partial toleration whitelist works": {
			Whitelist: []core.Toleration{
				{
					Key:      "dedicated",
					Operator: "*",
					Value:    "*",
					Effect:   "*",
				},
			},
			PodTolerations: []core.Toleration{
				{
					Key:      "dedicated",
					Operator: core.TolerationOpEqual,
					Value:    "ingress",
					Effect:   core.TaintEffectNoSchedule,
				},
			},
		},
		"check multiple whitelist tolerations work": {
			Whitelist: []core.Toleration{
				{
					Key:      "dedicated",
					Operator: "Equal",
					Value:    "ingress",
					Effect:   "NoSchedule",
				},
				{
					Key:      "dedicated",
					Operator: "Equal",
					Value:    "compute",
					Effect:   "NoSchedule",
				},
			},
			PodTolerations: []core.Toleration{
				{
					Key:      "dedicated",
					Operator: core.TolerationOpEqual,
					Value:    "ingress",
					Effect:   core.TaintEffectNoSchedule,
				},
			},
		},
	}
	newTestAuthorizer(t, nil).runChecks(t, checks)
}

func TestDefaultWhitelist(t *testing.T) {
	c := newTestAuthorizer(t, nil)
	c.config.DefaultWhitelist = []core.Toleration{
		{
			Key:      "dedicated",
			Operator: "*",
			Value:    "compute",
			Effect:   "*",
		},
	}
	checks := map[string]tolerationCheck{
		"check the default white is being used": {
			PodTolerations: []core.Toleration{
				{
					Key:      "dedicated",
					Operator: core.TolerationOpEqual,
					Value:    "ingress",
					Effect:   core.TaintEffectNoSchedule,
				},
			},
			Errors: field.ErrorList{
				{
					Field:    "spec.tolerations[0]",
					BadValue: "dedicated=ingress:NoSchedule",
					Type:     field.ErrorTypeInvalid,
					Detail:   "toleration denied by whitelist",
				},
			},
		},
	}
	c.runChecks(t, checks)
}

func TestDefaultWhitelistOverride(t *testing.T) {
	c := newTestAuthorizer(t, nil)
	c.config.DefaultWhitelist = []core.Toleration{
		{
			Key:      "dedicated",
			Operator: "*",
			Value:    "compute",
			Effect:   "*",
		},
	}
	checks := map[string]tolerationCheck{
		"check the default whitelist if overriden by the namespace": {
			Whitelist: []core.Toleration{
				{
					Key:      "dedicated",
					Operator: core.TolerationOpEqual,
					Value:    "ingress",
					Effect:   core.TaintEffectNoSchedule,
				},
			},
			PodTolerations: []core.Toleration{
				{
					Key:      "dedicated",
					Operator: core.TolerationOpEqual,
					Value:    "ingress",
					Effect:   core.TaintEffectNoSchedule,
				},
			},
		},
	}
	c.runChecks(t, checks)
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

func (c *testAuthorizer) runChecks(t *testing.T, checks map[string]tolerationCheck) {
	for desc, check := range checks {
		cx := newTestContext()

		pod := check.Pod
		if pod == nil {
			pod = newTestPod()
		}
		if len(check.PodTolerations) > 0 {
			pod.Spec.Tolerations = check.PodTolerations
		}
		namespace := check.Namespace
		if namespace == nil {
			namespace = newTestNamespace()
		}
		if len(check.Whitelist) > 0 {
			encoded, err := json.Marshal(&check.Whitelist)
			require.NoError(t, err, "case '%s' unable to encode whitelist", desc)
			namespace.Annotations[cx.Annotation(Name)] = string(encoded)
		}
		cx.Client.CoreV1().Namespaces().Create(context.TODO(), namespace, metav1.CreateOptions{})
		cx.Object = pod

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

func newTestNamespace() *core.Namespace {
	return &core.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test",
			Annotations: make(map[string]string, 0),
		},
	}
}

func newTestPod() *core.Pod {
	return &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-",
			Namespace: "test",
		},
		Spec: core.PodSpec{
			Containers: []core.Container{{Name: "nginx-", Image: "nginx:latet"}},
		},
	}
}

func newTestConfig() *Config {
	return &Config{}
}
