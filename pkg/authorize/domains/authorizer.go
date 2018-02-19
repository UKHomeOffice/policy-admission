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
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"github.com/patrickmn/go-cache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
	extensions "k8s.io/kubernetes/pkg/apis/extensions"
)

// authorizer is used to wrap the interaction with the psp runtime
type authorizer struct {
	// the configuration for the enforcer
	config *Config
}

// Admit is responsible for authorizing the pod
func (c *authorizer) Admit(client kubernetes.Interface, mcache *cache.Cache, object metav1.Object) field.ErrorList {
	var errs field.ErrorList

	ingress, ok := object.(*extensions.Ingress)
	if !ok {
		return append(errs, field.InternalError(field.NewPath("object").Child(reflect.TypeOf(object).String()),
			errors.New("invalid object, expected ingress")))
	}
	// @step: get namespace for this object
	namespace, err := utils.GetCachedNamespace(client, mcache, ingress.Namespace)
	if err != nil {
		return append(errs, field.InternalError(field.NewPath("namespace"), err))
	}

	// @check the annotation exists on the namespace
	annotation, found := namespace.GetAnnotations()[Annotation]
	if !found {
		return append(errs, field.Invalid(field.NewPath("namespace", "annotations").Key(Annotation), "", "no whitelist annotation"))
	}

	// @check the whitelist is not empty
	if annotation == "" {
		return append(errs, field.Invalid(field.NewPath("namespace", "annotations").Key(Annotation), "", "whitelist is empty"))
	}
	whitelist := strings.Split(annotation, ",")

	for index, rule := range ingress.Spec.Rules {
		if found := hasDomain(strings.TrimSpace(rule.Host), whitelist); found {
			return errs
		}
		path := field.NewPath("spec", "rules").Index(index).Child("host")
		errs = append(errs, field.Invalid(path, rule.Host, "host is not permitted by namespace policy"))
	}

	return errs
}

// hasDomain checks the domain exists with in the whitelist
// e.g hostname.namespace.svc.cluster.local or *.namespace.svc.cluster.local
func hasDomain(hostname string, whitelist []string) bool {
	for _, domain := range whitelist {
		domain = strings.Replace(domain, " ", "", -1)
		wildcard := strings.HasPrefix(domain, "*.")
		switch wildcard {
		case true:
			fqdn := fmt.Sprintf("%s.%s", strings.Split(hostname, ".")[0], strings.TrimPrefix(domain, "*."))
			if hostname == fqdn {
				return true
			}
		default:
			// @check there is an exact match between hostname and whitelist
			if hostname == domain {
				return true
			}
		}
	}

	return false
}

// FilterOn returns the authorizer handle
func (c *authorizer) FilterOn() api.Filter {
	return api.Filter{
		IgnoreNamespaces: c.config.IgnoreNamespaces,
		Kind:             api.FilterIngresses,
	}
}

// Name returns the name of the provider
func (c *authorizer) Name() string {
	return Name
}

// New creates and returns an authorizer
func New(config *Config) (api.Authorize, error) {
	if config == nil {
		config = NewDefaultConfig()
	}

	return &authorizer{config: config}, nil
}

// NewFromFile reads the configuration path and returns the authorizer
func NewFromFile(path string) (api.Authorize, error) {
	if path == "" {
		return New(nil)
	}
	cfg := &Config{}
	if err := utils.NewConfig(path).Read(cfg); err != nil {
		return nil, err
	}

	return New(cfg)
}
