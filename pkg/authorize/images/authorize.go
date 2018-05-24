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

package images

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"github.com/patrickmn/go-cache"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
)

type authorizer struct {
	// config the configuration for the service
	config *Config
	// policies is a collection of regexes
	policies []*regexp.Regexp
	// policyCache is a cached to whitelists
	policyCache *cache.Cache
}

// Admit is responsible for authorizing the pod
func (c *authorizer) Admit(client kubernetes.Interface, mcache *cache.Cache, object metav1.Object) field.ErrorList {
	var errs field.ErrorList
	var apply []*regexp.Regexp

	pod, ok := object.(*core.Pod)
	if !ok {
		return append(errs, field.InternalError(field.NewPath("object"), errors.New("invalid object, expected Pod")))
	}

	apply = append(apply, c.policies...)

	// @step: get namespace for this object
	namespace, err := utils.GetCachedNamespace(client, mcache, pod.Namespace)
	if err != nil {
		return append(errs, field.InternalError(field.NewPath("namespace"), err))
	}

	// @check if there is a namespace override
	annotation, found := namespace.GetAnnotations()[Annotation]
	if found {
		override, errlist := c.parseImagePolicyAnnotation(annotation)
		if len(errs) > 0 {
			return append(errs, errlist...)
		}
		apply = append(apply, override...)
	}

	if len(apply) <= 0 {
		return errs
	}

	// @check the pods comply with image policy against the pods and init containers
	errs = append(errs, c.validateImagePolicy(apply, pod.Spec.InitContainers)...)
	errs = append(errs, c.validateImagePolicy(apply, pod.Spec.Containers)...)

	return errs
}

// validateImagePolicy checks the the image complys with policy
func (c *authorizer) validateImagePolicy(policies []*regexp.Regexp, containers []core.Container) field.ErrorList {
	var errs field.ErrorList
	for i, x := range containers {
		var admit bool
		for _, matcher := range policies {
			if matched := matcher.MatchString(x.Image); matched {
				admit = true
				break
			}
		}
		if !admit {
			path := field.NewPath("spec", "containers").Index(i).Child("image")
			errs = append(errs, field.Invalid(path, x.Image, fmt.Sprintf("image: %s denied by policy", x.Image)))
		}
	}

	return errs
}

// parseImagePolicyAnnotation is responsible for parsing the namespace annotation
func (c *authorizer) parseImagePolicyAnnotation(annotation string) (list []*regexp.Regexp, errs field.ErrorList) {
	for _, x := range strings.Split(annotation, ",") {
		x = strings.TrimLeft(x, " ")
		x = strings.TrimRight(x, " ")

		matcher, found := c.policyCache.Get(x)
		if found {
			list = append(list, (matcher).(*regexp.Regexp))
			continue
		}

		// @step: compile the regexp, cache and add to the list
		r, err := regexp.Compile(x)
		if err != nil {
			errs = append(errs, field.Invalid(field.NewPath("whitelist"), x, "image policy regex invalid"))
			continue
		}

		// @step: add to the cache and the list
		c.policyCache.Add(x, r, time.Duration(20*time.Minute))
		list = append(list, r)
	}

	return
}

// Name is the authorizer
func (c *authorizer) Name() string {
	return Name
}

// FilterOn returns the authorizer handle
func (c *authorizer) FilterOn() api.Filter {
	return api.Filter{
		IgnoreNamespaces: c.config.IgnoreNamespaces,
		Kind:             api.FilterPods,
	}
}

// New creates and returns a image authorizer
func New(config *Config) (api.Authorize, error) {
	if config == nil {
		config = NewDefaultConfig()
	}
	var policies []*regexp.Regexp

	for _, regex := range config.ImagePolicies {
		r, err := regexp.Compile(regex)
		if err != nil {
			return nil, fmt.Errorf("policy: %s, invalid regex: %s", regex, err)
		}
		policies = append(policies, r)
	}

	return &authorizer{
		config:      config,
		policies:    policies,
		policyCache: cache.New(time.Duration(10*time.Minute), time.Duration(10*time.Minute)),
	}, nil
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
