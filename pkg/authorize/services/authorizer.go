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
	"errors"
	"reflect"
	"strings"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"github.com/patrickmn/go-cache"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
)

// authorizer is used to wrap the interactions
type authorizer struct {
	config *Config
}

// Admit is responsible for authorizing the service
func (c *authorizer) Admit(client kubernetes.Interface, mcache *cache.Cache, object metav1.Object) field.ErrorList {
	var errs field.ErrorList

	svc, ok := object.(*core.Service)
	if !ok {
		return append(errs, field.InternalError(field.NewPath("object").Child(reflect.TypeOf(object).String()),
			errors.New("invalid object, expected service")))
	}

	var whitelist []string
	whitelist = append(whitelist, c.config.Whitelist...)

	// @step: get namespace for this object
	namespace, err := utils.GetCachedNamespace(client, mcache, svc.Namespace)
	if err != nil {
		return append(errs, field.InternalError(field.NewPath("namespace"), err))
	}

	// @check if the namespace has a whitelist
	annotation, found := namespace.GetAnnotations()[Annotation]
	if found {
		whitelist = append(whitelist, strings.Split(strings.TrimSpace(annotation), ",")...)
	}

	if permitted := c.validateService(svc, whitelist); !permitted {
		errs = append(errs, field.Invalid(field.NewPath("spec", "type"), svc.Spec.Type, "service type denied by cluster policy"))
	}

	return errs
}

// validateService checks the service type is permitted by the whitelist
func (c *authorizer) validateService(service *core.Service, whitelist []string) bool {
	for _, x := range whitelist {
		if service.Spec.Type == core.ServiceType(x) {
			return true
		}
	}

	return false
}

// Name returns the name of the provider
func (c *authorizer) Name() string {
	return Name
}

// FilterOn returns the authorizer handle
func (c *authorizer) FilterOn() api.Filter {
	return api.Filter{
		IgnoreNamespaces: c.config.IgnoreNamespaces,
		Kind:             api.FilterServices,
	}
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
