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
	"encoding/json"
	"fmt"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
	core "k8s.io/kubernetes/pkg/api"
)

// authorizer is responsible for validating the tolerations
type authorizer struct {
	// config is the configuration for service
	config *Config
}

// authorize is responsible for authorizer a taint
func (c *authorizer) Admit(_ kubernetes.Interface, namespace *v1.Namespace, object metav1.Object) field.ErrorList {
	var errs field.ErrorList
	var whitelist []core.Toleration

	pod := object.(*core.Pod)

	// @check of the pod has a any specified tolerations
	if len(pod.Spec.Tolerations) <= 0 {
		return errs
	}

	// we use the default tolerations if any
	whitelist = append(whitelist, c.config.DefaultWhitelist...)

	// @check if the namespace has a white list on toleration allowed and that we have a list
	annotation, found := namespace.GetAnnotations()[Annotation]
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
			errs = append(errs, field.Forbidden(field.NewPath("whitelist"), fmt.Sprintf("pod tolerations %d denied by whitelist", i)))
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
func (c *authorizer) FilterOn() api.Filter {
	return api.Filter{
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
