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

package kubecertmanager

import (
	"context"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"

	"github.com/UKHomeOffice/policy-admission/pkg/api"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/fake"
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
	config := NewDefaultConfig()
	config.InternalIngressHostname = "ingress-internal.acp.example.com"
	config.ExternalIngressHostname = "ingress-external.acp.example.com"
	config.HostedDomains = []string{"example.com"}

	checks := map[string]kubeCertCheck{
		"check that the ingress is allowed through": {},
		"check valid cert-manager.io internal ingress is ok": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-internal",
				"cert-manager.io/enabled":     "true",
			},
			Labels:   map[string]string{"cert-manager.io/solver": "route53"},
			Hosts:    []string{"site.example.com"},
			Resolves: config.InternalIngressHostname,
		},
		"check valid cert-manager.io external ingress is ok": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Hosts:    []string{"site.example.com"},
			Resolves: config.ExternalIngressHostname,
		},
		"check valid cert-manager.io external ingress with explicit valid solver is ok": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Labels:   map[string]string{"cert-manager.io/solver": "http01"},
			Hosts:    []string{"site.example.com"},
			Resolves: config.ExternalIngressHostname,
		},
		"check an externally hosted domain with internal ingress cert-manager.io annotations is denied": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-internal",
				"cert-manager.io/enabled":     "true",
			},
			Labels:   map[string]string{"cert-manager.io/solver": "route53"},
			Hosts:    []string{"site.nohere.com"},
			Resolves: config.InternalIngressHostname,
			Errors: field.ErrorList{
				{
					Field:    "spec.rules[0].host",
					BadValue: "site.nohere.com",
					Type:     field.ErrorTypeInvalid,
					Detail:   "domain is not hosted internally and thus denied",
				},
			},
		},
		"check a cert-manager.io internal ingress is denied when the dns does not resolve": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-internal",
				"cert-manager.io/enabled":     "true",
			},
			Labels:   map[string]string{"cert-manager.io/solver": "route53"},
			Hosts:    []string{"site.example.com"},
			Resolves: "bad.hostname",
			Errors: field.ErrorList{
				{
					Field:    "spec.rules[0].host",
					BadValue: "site.example.com",
					Type:     field.ErrorTypeInvalid,
					Detail:   "the hostname: site.example.com is not pointed to the internal ingress dns name ingress-internal.acp.example.com",
				},
			},
		},
		"check a cert-manager.io internal ingress is permitted when the dns check is disabled": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-internal",
				"cert-manager.io/enabled":     "true",
			},
			Labels: map[string]string{"cert-manager.io/solver": "route53"},
			Namespace: map[string]string{
				"policy-admission.acp.homeoffice.gov.uk/kubecertmanager/enable-dns-check": "false",
			},
			Hosts:    []string{"site.example.com"},
			Resolves: "bad.hostname",
		},
		"check a cert-manager.io external ingress is denied when the dns does not resolve": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Hosts:    []string{"site.nohere.com"},
			Resolves: "bad.hostname",
			Errors: field.ErrorList{
				{
					Field:    "spec.rules[0].host",
					BadValue: "site.nohere.com",
					Type:     field.ErrorTypeInvalid,
					Detail:   "the hostname: site.nohere.com is not pointed to the external ingress dns name ingress-external.acp.example.com",
				},
			},
		},
		"check a cert-manager.io external ingress is permitted when the dns check is disabled": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Namespace: map[string]string{
				"policy-admission.acp.homeoffice.gov.uk/kubecertmanager/enable-dns-check": "false",
			},
			Hosts:    []string{"site.nohere.com"},
			Resolves: "bad.hostname",
		},
		"check a cert-manager.io external ingress is denied when dns check is enabled": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Namespace: map[string]string{
				"policy-admission.acp.homeoffice.gov.uk/kubecertmanager/enable-dns-check": "true",
			},
			Hosts:    []string{"site.nohere.com"},
			Resolves: "bad.hostname",
			Errors: field.ErrorList{
				{
					Field:    "spec.rules[0].host",
					BadValue: "site.nohere.com",
					Type:     field.ErrorTypeInvalid,
					Detail:   "the hostname: site.nohere.com is not pointed to the external ingress dns name ingress-external.acp.example.com",
				},
			},
		},
		"check a cert-manager.io external default value of dns check is true": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Namespace: map[string]string{
				"policy-admission.acp.homeoffice.gov.uk/kubecertmanager/enable-dns-check": "bad_value",
			},
			Hosts:    []string{"site.nohere.com"},
			Resolves: "bad.hostname",
			Errors: field.ErrorList{
				{
					Field:    "spec.rules[0].host",
					BadValue: "site.nohere.com",
					Type:     field.ErrorTypeInvalid,
					Detail:   "the hostname: site.nohere.com is not pointed to the external ingress dns name ingress-external.acp.example.com",
				},
			},
		},
		"check a cert-manager.io external ingress permitted when resolves": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Hosts:    []string{"site.nohere.com"},
			Resolves: config.ExternalIngressHostname,
		},
		"check missing cert-manager.io/enabled annotation is denied": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/foo":         "bar",
			},
			Hosts: []string{"site.example.com"},
			Errors: field.ErrorList{
				{
					Field:    "metadata.annotations.cert-manager.io/enabled",
					BadValue: "",
					Type:     field.ErrorTypeInvalid,
					Detail:   "cert-manager.io annotations or labels are present, but annotation cert-manager.io/enabled: \"true\" is missing",
				},
			},
		},
		"check cert-manager.io internal ingress with missing label is denied": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-internal",
				"cert-manager.io/enabled":     "true",
			},
			Hosts:    []string{"site.example.com"},
			Resolves: config.InternalIngressHostname,
			Errors: field.ErrorList{
				{
					Field:    "metadata.labels.cert-manager.io/solver",
					BadValue: "",
					Type:     field.ErrorTypeInvalid,
					Detail:   "nginx-internal has been specified as an annotation for kubernetes.io/ingress.class but label cert-manager.io/solver is missing or not set to route53",
				},
			},
		},
		"check cert-manager.io internal ingress with invalid solver is denied": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-internal",
				"cert-manager.io/enabled":     "true",
			},
			Labels:   map[string]string{"cert-manager.io/solver": "bad"},
			Hosts:    []string{"site.example.com"},
			Resolves: config.InternalIngressHostname,
			Errors: field.ErrorList{
				{
					Field:    "metadata.labels.cert-manager.io/solver",
					BadValue: "bad",
					Type:     field.ErrorTypeInvalid,
					Detail:   "nginx-internal has been specified as an annotation for kubernetes.io/ingress.class but label cert-manager.io/solver is missing or not set to route53",
				},
			},
		},
		"check cert-manager.io external ingress with route53 solver is ok": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Labels:   map[string]string{"cert-manager.io/solver": "route53"},
			Hosts:    []string{"site.example.com"},
			Resolves: config.ExternalIngressHostname,
		},
		"check cert-manager.io external ingress with invalid solver is denied": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Labels:   map[string]string{"cert-manager.io/solver": "bad"},
			Hosts:    []string{"site.example.com"},
			Resolves: config.ExternalIngressHostname,
			Errors: field.ErrorList{
				{
					Field:    "metadata.labels.cert-manager.io/solver",
					BadValue: "bad",
					Type:     field.ErrorTypeInvalid,
					Detail:   "nginx-external has been specified as an annotation for kubernetes.io/ingress.class but label cert-manager.io/solver has an invalid value: expecting http01, route53 or no solver annotation",
				},
			},
		},
		"check cert-manager.io external ingress with missing ingress.class is denied": {
			Annotations: map[string]string{
				"cert-manager.io/enabled": "true",
			},
			Hosts: []string{"site.example.com"},
			Errors: field.ErrorList{
				{
					Field:    "spec.ingressclassname",
					BadValue: "",
					Type:     field.ErrorTypeInvalid,
					Detail:   "field ingressClassName is missing; please specify a value of either nginx-internal or nginx-external",
				},
				{
					Field:    "metadata.annotations.kubernetes.io/ingress.class",
					BadValue: "",
					Type:     field.ErrorTypeInvalid,
					Detail:   "annotation kubernetes.io/ingress.class is missing; please specify a value of either nginx-internal or nginx-external",
				},
			},
		},
		"check cert-manager.io external ingress with invalid ingress.class is denied": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "bad",
				"cert-manager.io/enabled":     "true",
			},
			Hosts: []string{"site.example.com"},
			Errors: field.ErrorList{
				{
					Field:    "spec.ingressclassname",
					BadValue: "",
					Type:     field.ErrorTypeInvalid,
					Detail:   "field ingressClassName is invalid; please specify a value of either nginx-internal or nginx-external",
				},
				{
					Field:    "metadata.annotations.kubernetes.io/ingress.class",
					BadValue: "bad",
					Type:     field.ErrorTypeInvalid,
					Detail:   "annotation kubernetes.io/ingress.class is invalid; please specify a value of either nginx-internal or nginx-external",
				},
			},
		},
		"check cert-manager.io external ingress with a common name of 63 characters is ok": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Hosts:    []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com"},
			Resolves: config.ExternalIngressHostname,
		},
		"check cert-manager.io external ingress with a common name of 64 characters is denied": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Hosts:    []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com"},
			Resolves: config.ExternalIngressHostname,
			Errors: field.ErrorList{
				{
					Field:    "spec.tls[0].hosts[0]",
					BadValue: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
					Type:     field.ErrorTypeInvalid,
					Detail:   "commonName in certificates should be no more than 63 characters (but additional hosts can be); look at https://ukhomeoffice.github.io/application-container-platform/how-to-docs/cert-manager.html for a work-around allowing you to specify a long host name",
				},
			},
		},
		"check cert-manager.io external ingress with a common name of 63 characters or less but additional hosts with long names is ok": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Hosts: []string{
				"short-name.example.com",
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
			},
			Resolves: config.ExternalIngressHostname,
		},
		"check cert-manager managed ingress with both v0.8 and v0.11+ annotations is denied": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
				"certmanager.k8s.io/foo":      "bar",
			},
			Hosts: []string{"site.example.com"},
			Errors: field.ErrorList{
				{
					Field:    "metadata.annotations",
					BadValue: "",
					Type:     field.ErrorTypeInvalid,
					Detail:   "this ingress should be managed by a single certificate manager; found prefixes [cert-manager.io certmanager.k8s.io] in annotations or labels; please use only cert-manager.io",
				},
			},
		},
		"check annotations of 2 different cert managers is denied": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
				"stable.k8s.psg.io/kcm.foo":   "bar",
			},
			Hosts: []string{"site.example.com"},
			Errors: field.ErrorList{
				{
					Field:    "metadata.annotations",
					BadValue: "",
					Type:     field.ErrorTypeInvalid,
					Detail:   "this ingress should be managed by a single certificate manager; found prefixes [cert-manager.io stable.k8s.psg.io/kcm] in annotations or labels; please use only cert-manager.io",
				},
			},
		},
		"check labels of 2 different cert managers is denied": {
			Annotations: map[string]string{"kubernetes.io/ingress.class": "nginx-external"},
			Labels: map[string]string{
				"cert-manager.io/baz":       "fooz",
				"stable.k8s.psg.io/kcm.foo": "bar",
			},
			Hosts: []string{"site.example.com"},
			Errors: field.ErrorList{
				{
					Field:    "metadata.annotations",
					BadValue: "",
					Type:     field.ErrorTypeInvalid,
					Detail:   "this ingress should be managed by a single certificate manager; found prefixes [cert-manager.io stable.k8s.psg.io/kcm] in annotations or labels; please use only cert-manager.io",
				},
			},
		},
		"check annotation and label of 2 different cert managers is denied": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Labels: map[string]string{"stable.k8s.psg.io/kcm.foo": "bar"},
			Hosts:  []string{"site.example.com"},
			Errors: field.ErrorList{
				{
					Field:    "metadata.annotations",
					BadValue: "",
					Type:     field.ErrorTypeInvalid,
					Detail:   "this ingress should be managed by a single certificate manager; found prefixes [cert-manager.io stable.k8s.psg.io/kcm] in annotations or labels; please use only cert-manager.io",
				},
			},
		},
		// what about same check on Certificates? change js script?
		"check cert-manager.io internal ingress with kubernetes.io/tls-acme annotation is denied": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-internal",
				"cert-manager.io/enabled":     "true",
				"kubernetes.io/tls-acme":      "true",
			},
			Labels:   map[string]string{"cert-manager.io/solver": "route53"},
			Hosts:    []string{"site.example.com"},
			Resolves: config.InternalIngressHostname,
			Errors: field.ErrorList{
				{
					Field:    "metadata.annotations.kubernetes.io/tls-acme",
					BadValue: "true",
					Type:     field.ErrorTypeInvalid,
					Detail:   "you have specified route53 as the cert-manager solver to use; please remove the kubernetes.io/tls-acme annotation",
				},
			},
		},
		"check cert-manager.io external ingress with route53 solver and kubernetes.io/tls-acme annotation is denied": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
				"kubernetes.io/tls-acme":      "true",
			},
			Labels:   map[string]string{"cert-manager.io/solver": "route53"},
			Hosts:    []string{"site.example.com"},
			Resolves: config.ExternalIngressHostname,
			Errors: field.ErrorList{
				{
					Field:    "metadata.annotations.kubernetes.io/tls-acme",
					BadValue: "true",
					Type:     field.ErrorTypeInvalid,
					Detail:   "you have specified route53 as the cert-manager solver to use; please remove the kubernetes.io/tls-acme annotation",
				},
			},
		},
		"check psg annotations are rejected": {
			Annotations: map[string]string{
				"stable.k8s.psg.io/kcm-foo": "bar",
			},
			Errors: field.ErrorList{
				{
					Field:    "metadata",
					BadValue: "stable.k8s.psg.io/kcm",
					Type:     field.ErrorTypeInvalid,
					Detail:   "certificate manager stable.k8s.psg.io/kcm is no longer supported; please use cert-manager.io in annotations or labels",
				},
			},
		},
		"check psg labels are rejected": {
			Labels: map[string]string{
				"stable.k8s.psg.io/kcm-foo": "bar",
			},
			Errors: field.ErrorList{
				{
					Field:    "metadata",
					BadValue: "stable.k8s.psg.io/kcm",
					Type:     field.ErrorTypeInvalid,
					Detail:   "certificate manager stable.k8s.psg.io/kcm is no longer supported; please use cert-manager.io in annotations or labels",
				},
			},
		},
		"check old certmanager.k8s.io annotations are rejected": {
			Annotations: map[string]string{
				"certmanager.k8s.io/foo": "bar",
			},
			Errors: field.ErrorList{
				{
					Field:    "metadata",
					BadValue: "certmanager.k8s.io",
					Type:     field.ErrorTypeInvalid,
					Detail:   "certificate manager certmanager.k8s.io is no longer supported; please use cert-manager.io in annotations or labels",
				},
			},
		},
		"check old certmanager.k8s.io labels are rejected": {
			Labels: map[string]string{
				"certmanager.k8s.io/foo": "bar",
			},
			Errors: field.ErrorList{
				{
					Field:    "metadata",
					BadValue: "certmanager.k8s.io",
					Type:     field.ErrorTypeInvalid,
					Detail:   "certificate manager certmanager.k8s.io is no longer supported; please use cert-manager.io in annotations or labels",
				},
			},
		},
		// IngressClassName field checks
		"check internal ingress with ingressclassname is ok": {
			Annotations: map[string]string{
				"cert-manager.io/enabled": "true",
			},
			Labels:           map[string]string{"cert-manager.io/solver": "route53"},
			Hosts:            []string{"site.example.com"},
			IngressClassName: "nginx-internal",
			Resolves:         config.InternalIngressHostname,
		},
		"check external ingress with ingressclassname is ok": {
			Annotations: map[string]string{
				"cert-manager.io/enabled": "true",
			},
			Hosts:            []string{"site.example.com"},
			IngressClassName: "nginx-external",
			Resolves:         config.ExternalIngressHostname,
		},
		"check ingress invalid ingressclassname is denied": {
			Annotations: map[string]string{
				"cert-manager.io/enabled": "true",
			},
			Labels:           map[string]string{"cert-manager.io/solver": "route53"},
			Hosts:            []string{"site.example.com"},
			IngressClassName: "bad",
			Errors: field.ErrorList{
				{
					Field:    "spec.ingressclassname",
					BadValue: "bad",
					Type:     field.ErrorTypeInvalid,
					Detail:   "field ingressClassName is invalid; please specify a value of either nginx-internal or nginx-external",
				},
				{
					Field:    "metadata.annotations.kubernetes.io/ingress.class",
					BadValue: "",
					Type:     field.ErrorTypeInvalid,
					Detail:   "annotation kubernetes.io/ingress.class is invalid; please specify a value of either nginx-internal or nginx-external",
				},
			},
		},
		"check internal ingress with annotation and ingressclassname is ok": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-internal",
				"cert-manager.io/enabled":     "true",
			},
			Labels:           map[string]string{"cert-manager.io/solver": "route53"},
			Hosts:            []string{"site.example.com"},
			IngressClassName: "nginx-internal",
			Resolves:         config.InternalIngressHostname,
		},
		// this technically is allowed by the ingress controller (the ingressClassName field will take precedence over the annotation)
		// but no-one should really be doing this anyway (e.g. they could change it so that the annotation takes precedence)
		"check ingress with different annotation and ingressclassname is denied": {
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx-external",
				"cert-manager.io/enabled":     "true",
			},
			Hosts:            []string{"site.example.com"},
			IngressClassName: "nginx-internal",
			Resolves:         config.InternalIngressHostname,
			Errors: field.ErrorList{
				{
					Field:    "spec.ingressclassname",
					BadValue: "nginx-internal",
					Type:     field.ErrorTypeInvalid,
					Detail:   "field ingressClassName and annotation kubernetes.io/ingress.class should be set to the same value; please specify a value of either nginx-internal or nginx-external",
				},
			},
		},
		"check an externally hosted domain with internal ingress ingressclassname is denied": {
			Annotations: map[string]string{
				"cert-manager.io/enabled": "true",
			},
			Labels:           map[string]string{"cert-manager.io/solver": "route53"},
			Hosts:            []string{"site.nohere.com"},
			IngressClassName: "nginx-internal",
			Resolves:         config.InternalIngressHostname,
			Errors: field.ErrorList{
				{
					Field:    "spec.rules[0].host",
					BadValue: "site.nohere.com",
					Type:     field.ErrorTypeInvalid,
					Detail:   "domain is not hosted internally and thus denied",
				},
			},
		},
	}
	newTestAuthorizer(t, config).runChecks(t, checks)
}

type kubeCertCheck struct {
	Annotations      map[string]string
	Namespace        map[string]string
	Errors           field.ErrorList
	Hosts            []string
	Labels           map[string]string
	IngressClassName string
	Resolves         string
}

type testAuthorizer struct {
	config *Config
	svc    api.Authorize
}

type testResolver struct {
	hostname string
}

func (t *testResolver) GetCNAME(string) (string, error) {
	return t.hostname, nil
}

func newTestAuthorizer(t *testing.T, config *Config) *testAuthorizer {
	if config == nil {
		config = newTestConfig()
	}
	c, err := New(config)
	c.(*authorizer).resolve = &testResolver{}
	if err != nil {
		t.Fatalf("unable to create authorizer: %s", err)
	}

	return &testAuthorizer{config: config, svc: c}
}

func (c *testAuthorizer) runChecks(t *testing.T, checks map[string]kubeCertCheck) {
	for desc, check := range checks {
		cx := newTestContext()

		cx.Client.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test",
				Annotations: check.Namespace,
			},
		}, metav1.CreateOptions{})

		if check.Resolves != "" {
			c.svc.(*authorizer).resolve = &testResolver{hostname: check.Resolves}
		}

		ingress := newDefaultIngress()
		ingress.Spec.TLS = make([]networkingv1.IngressTLS, 1)
		for _, x := range check.Hosts {
			ingress.Spec.Rules = append(ingress.Spec.Rules, networkingv1.IngressRule{Host: x})
			ingress.Spec.TLS[0].Hosts = append(ingress.Spec.TLS[0].Hosts, x)
		}
		ingress.ObjectMeta.Annotations = check.Annotations
		ingress.ObjectMeta.Labels = check.Labels
		ingress.Spec.IngressClassName = &check.IngressClassName
		cx.Object = ingress

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

func newDefaultIngress() *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-",
			Namespace: "test",
		},
		Spec: networkingv1.IngressSpec{},
	}
}

func newTestConfig() *Config {
	return &Config{
		IgnoreNamespaces: []string{"kube-system"},
	}
}
