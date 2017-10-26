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
	"errors"
	"fmt"
	"reflect"
	"regexp"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"github.com/patrickmn/go-cache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
	core "k8s.io/kubernetes/pkg/api"
)

// authorizer is used to wrap the interaction with the psp runtime
type authorizer struct {
	// the configuration for the enforcer
	config *Config
}

// Admit is responsible for authorizing the pod
func (c *authorizer) Admit(client kubernetes.Interface, mcache *cache.Cache, object metav1.Object) field.ErrorList {
	var errs field.ErrorList

	namespace, ok := object.(*core.Namespace)
	if !ok {
		return append(errs, field.InternalError(field.NewPath("object").Child(reflect.TypeOf(object).String()),
			errors.New("invalid object, expected namespace")))
	}

	return append(errs, c.validateAttributes(namespace)...)
}

// validateAttributes is responsible for validating the namespace against the attributes
func (c *authorizer) validateAttributes(namespace *core.Namespace) field.ErrorList {
	var errs field.ErrorList

	for _, a := range c.config.Attributes {
		var value string
		var found bool
		switch a.Type {
		case TypeAnnotation:
			value, found = namespace.GetAnnotations()[a.Name]
		case TypeLabel:
			value, found = namespace.GetLabels()[a.Name]
		}
		// @check if the attribute is required
		if a.Required && !found {
			errs = append(errs, field.Invalid(field.NewPath(a.Name), "", fmt.Sprintf("required %s missing", a.Type)))
		}
		if a.Required && value == "" {
			errs = append(errs, field.Invalid(field.NewPath(a.Name), "", fmt.Sprintf("required %s empty", a.Type)))
		}
		if a.compiled != nil && value != "" {
			if matched := a.compiled.MatchString(value); !matched {
				errs = append(errs, field.Invalid(field.NewPath(a.Name), value, fmt.Sprintf("invalid value for %s", a.Type)))
			}
		}
	}

	return errs
}

// FilterOn returns the authorizer handle
func (c *authorizer) FilterOn() api.Filter {
	return api.Filter{
		IgnoreNamespaces: c.config.IgnoreNamespaces,
		Kind:             api.FilterNamespace,
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
	for i, a := range config.Attributes {
		if err := a.IsValid(); err != nil {
			return nil, fmt.Errorf("invalid attribute[%d]: name: %s, reason: %s", i, a.Name, err)
		}
		if a.Validate != "" {
			a.compiled, _ = regexp.Compile(a.Validate)
		}
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
