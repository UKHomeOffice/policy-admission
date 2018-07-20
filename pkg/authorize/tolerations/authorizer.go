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
	"errors"
	"fmt"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// authorizer is responsible for validating the tolerations
type authorizer struct {
	// config is the configuration for service
	config *Config
}

// authorize is responsible for authorizer a taint
func (c *authorizer) Admit(_ context.Context, cx *api.Context) field.ErrorList {
	var errs field.ErrorList
	var whitelist []core.Toleration

	pod, ok := cx.Object.(*core.Pod)
	if !ok {
		return append(errs, field.InternalError(field.NewPath("object"), errors.New("invalid object, expected pod")))
	}

	// @check of the pod has a any specified tolerations
	if len(pod.Spec.Tolerations) <= 0 {
		return errs
	}

	// we use the default tolerations if any
	whitelist = append(whitelist, c.config.DefaultWhitelist...)

	// @step: get namespace for this object
	namespace, err := utils.GetCachedNamespace(cx.Client, cx.Cache, pod.Namespace)
	if err != nil {
		return append(errs, field.InternalError(field.NewPath("namespace"), err))
	}

	// @check if the namespace has a white list on toleration allowed and that we have a list
	annotation, found := namespace.GetAnnotations()[cx.Annotation(Name)]
	if found {
		var override []core.Toleration
		if err := json.Unmarshal([]byte(annotation), &override); err != nil {
			return append(errs, field.Invalid(field.NewPath("whitelist"), annotation, "namespace whitelist is invalid"))
		}
		whitelist = append(whitelist, override...)
	}

	// @step: check the toleration is permitted via the whitelist
	for i, toleration := range pod.Spec.Tolerations {
		if matched := isWhiteListed(toleration, whitelist); !matched {
			errs = append(errs, field.Invalid(field.NewPath("spec", "tolerations").Index(i),
				fmt.Sprintf("%s=%s:%s", toleration.Key, toleration.Value, toleration.Effect),
				"toleration denied by whitelist"))
		}
	}

	return errs
}

// isWhiteListed is responsible for checks a toleration exists in the whitelist
func isWhiteListed(t core.Toleration, whitelist []core.Toleration) bool {
	// @step: iterate the tolerations and fail on the first non matching whitelist
	for _, x := range whitelist {
		if x.Key != "*" && t.Key != x.Key {
			continue
		}
		if x.Operator != "*" && t.Operator != x.Operator {
			continue
		}
		if x.Value != "*" && t.Value != x.Value {
			continue
		}
		if x.Effect != "*" && t.Effect != x.Effect {
			continue
		}
		// @check if all four conditionals have passed
		return true
	}

	return false
}

// Name returns the provider name
func (c *authorizer) Name() string {
	return Name
}

// FilterOn returns the authorizer handle
func (c *authorizer) FilterOn() *api.Filter {
	return &api.Filter{
		IgnoreNamespaces: c.config.IgnoreNamespaces,
		Kind:             api.FilterPods,
	}
}

// New is responsible for creating a taint authorizer
func New(config *Config) (api.Authorize, error) {
	if config == nil {
		config = NewDefaultConfig()
	}
	return &authorizer{config: config}, nil
}

// NewFromFile reads the configuration path and returns the typesr
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

// Stop is called when the authorizer is being shutdown
func (c *authorizer) Stop() error {
	return nil
}
