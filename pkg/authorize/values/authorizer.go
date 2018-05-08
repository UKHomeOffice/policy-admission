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

package values

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"github.com/patrickmn/go-cache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"

	"github.com/tidwall/gjson"
)

// authorizer is used to wrap the interaction with the psp runtime
type authorizer struct {
	// the configuration for the enforcer
	config *Config
}

// Admit is responsible for authorizing the pod
func (c *authorizer) Admit(client kubernetes.Interface, mcache *cache.Cache, object metav1.Object) field.ErrorList {
	var errs field.ErrorList

	// @step: validate the object
	return append(errs, c.validateObject(c.config.Matches, object)...)
}

// validateObject is responsible for validating the values on an object
func (c *authorizer) validateObject(matches []*Match, object metav1.Object) field.ErrorList {
	var errs field.ErrorList

	// @step: decode the content into json
	decoded, err := json.Marshal(object)
	if err != nil {
		return append(errs, field.InternalError(field.NewPath(""), fmt.Errorf("unable decode object: %s", err)))
	}

	// @step: iterate the matches and apply the filter is required
	for _, x := range matches {
		// @check if the match should ignored for this namespace
		if utils.Contained(object.GetNamespace(), x.Namespaces) {
			continue
		}

		// @step: attempt to find the value
		result := gjson.GetBytes(decoded, x.Path)

		if !result.Exists() && x.Required {
			return append(errs, field.Required(field.NewPath(x.Path), "value is missing"))
		}

		// @check the actual value
		c.validateValue(field.NewPath(x.Path), result, x, &errs)
	}

	return errs
}

// validateValue is responsible for checking the value against the match
func (c *authorizer) validateValue(path *field.Path, v gjson.Result, m *Match, errs *field.ErrorList) {
	if v.IsArray() {
		for _, e := range v.Array() {
			c.validateValue(path, e, m, errs)
		}

		return
	}

	if v.IsObject() {
		// @step: create the filter for the keys, @note this has already be input checked
		filter, _ := regexp.Compile(m.KeyFilter)

		// @step: iterate the keys, filter if required and match against the match
		for key, result := range v.Map() {
			if !filter.MatchString(key) {
				continue
			}
			path = path.Key(key)

			c.validateValue(path, result, m, errs)
		}

		return
	}

	// @step: the value is not an array or a map we need to convert to string and check the value
	filter, found := filters[m.Value]
	if !found {
		// @note: this has already been validated so it's cool not to check the error
		filter, _ = regexp.Compile(m.Value)
	}
	if !filter.MatchString(v.String()) {
		*errs = append(*errs, field.Invalid(path, v.String(), fmt.Sprintf("invalid user input, must match %s", filter.String())))
	}
}

// FilterOn returns the authorizer handle
func (c *authorizer) FilterOn() api.Filter {
	filter := api.FilterAll
	if c.config.FilterOn != "" {
		filter = c.config.FilterOn
	}

	return api.Filter{
		IgnoreNamespaces: c.config.IgnoreNamespaces,
		Kind:             filter,
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

	// @check: validate each of the matches is ok
	for i, x := range config.Matches {
		if x.Path == "" {
			return nil, fmt.Errorf("match[%d].path is not set", i)
		}
		if x.KeyFilter != "" {
			if _, err := regexp.Compile(x.KeyFilter); err != nil {
				return nil, fmt.Errorf("match[%d].key-filter is invalid: %s", i, err)
			}
		} else {
			x.KeyFilter = ".*"
		}
		if x.Value != "" {
			if _, err := regexp.Compile(x.Value); err != nil {
				return nil, fmt.Errorf("match[%d].value is invalid: %s", i, err)
			}
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
