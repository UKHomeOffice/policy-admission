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
	"errors"
	"reflect"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"github.com/patrickmn/go-cache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
	core "k8s.io/kubernetes/pkg/api"
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

	if svc.Spec.Type == core.ServiceTypeLoadBalancer {
		return append(errs, field.Invalid(field.NewPath("service"), svc.Spec.Type, "loadbalancer services are denied by policy"))
	}

	return errs
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
