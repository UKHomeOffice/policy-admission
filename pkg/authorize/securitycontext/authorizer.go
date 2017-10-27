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

package securitycontext

import (
	"errors"
	"fmt"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"github.com/patrickmn/go-cache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
	core "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/security/podsecuritypolicy"
)

// authorizer is used to wrap the interaction with the psp runtime
type authorizer struct {
	// the configuration for the enforcer
	config *Config
	// the enforcement providers
	providers map[string]podsecuritypolicy.Provider
}

// Admit is responsible for adding a policy to the enforcers
func (c *authorizer) Admit(client kubernetes.Interface, mcache *cache.Cache, object metav1.Object) field.ErrorList {
	var errs field.ErrorList

	pod, ok := object.(*core.Pod)
	if !ok {
		return append(errs, field.InternalError(field.NewPath("object"), errors.New("invalid object, expected pod")))
	}
	name := c.config.Default

	// @check is this namespace being ignored
	if utils.Contained(pod.Namespace, c.config.IgnoreNamespaces) {
		return errs
	}

	// @step: select the policy to apply against
	if override, found := c.config.defaultPolicy(pod.Namespace); found {
		name = override
	}

	// @step: get namespace for this object
	namespace, err := utils.GetCachedNamespace(client, mcache, pod.Namespace)
	if err != nil {
		return append(errs, field.InternalError(field.NewPath("namespace"), err))
	}

	// @check if the nanespace if annontated
	if selected, found := namespace.GetAnnotations()[Annotation]; found {
		name = selected
	}

	// @check the policy exists
	provider, found := c.providers[name]
	if !found {
		return append(errs, field.Invalid(field.NewPath("policy"), name, "policy does not exist"))
	}

	// @check if the pod violates the psp
	if errs = append(errs, c.validatePod(provider, pod)...); len(errs) > 0 {
		return errs
	}

	// @check if the init container are valid agains the policy
	errs = append(errs, c.validateContainers(provider, pod, pod.Spec.InitContainers)...)
	// @check the main containers to not invalidate the psp
	errs = append(errs, c.validateContainers(provider, pod, pod.Spec.Containers)...)

	return errs
}

// validatePod is responsible for valudating the pod spec against the psp
func (c *authorizer) validatePod(provider podsecuritypolicy.Provider, pod *core.Pod) field.ErrorList {
	sc, _, err := provider.CreatePodSecurityContext(pod)
	if err != nil {
		return field.ErrorList{{Type: field.ErrorTypeInternal, Detail: err.Error()}}
	}
	pod.Spec.SecurityContext = sc

	return provider.ValidatePodSecurityContext(pod, field.NewPath("spec", "securityContext"))
}

// validateContainers is responisble for iterating the containers and validating against the policy
func (c *authorizer) validateContainers(provider podsecuritypolicy.Provider, pod *core.Pod, containers []core.Container) field.ErrorList {
	for i, _ := range containers {
		// set some same defaults or take the pods default
		containers[i].SecurityContext = assignSecurityContext(pod, &containers[i])

		sc, _, err := provider.CreateContainerSecurityContext(pod, &containers[i])
		if err != nil {
			return field.ErrorList{{Type: field.ErrorTypeInternal, Detail: err.Error()}}
		}
		containers[i].SecurityContext = sc

		violations := provider.ValidateContainerSecurityContext(pod, &containers[i], field.NewPath("spec", "securityContext"))
		if len(violations) > 0 {
			return violations
		}
	}

	return field.ErrorList{}
}

// assignSecurityContext is responsible for assigning some defaults
func assignSecurityContext(pod *core.Pod, container *core.Container) *core.SecurityContext {
	isFalse := false
	if container.SecurityContext == nil {
		container.SecurityContext = &core.SecurityContext{}
	}
	if container.SecurityContext.RunAsNonRoot == nil {
		if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil {
			container.SecurityContext.RunAsNonRoot = pod.Spec.SecurityContext.RunAsNonRoot
		} else {
			container.SecurityContext.RunAsNonRoot = &isFalse
		}
	}
	if container.SecurityContext.RunAsUser == nil && pod.Spec.SecurityContext.RunAsUser != nil {
		container.SecurityContext.RunAsUser = pod.Spec.SecurityContext.RunAsUser
	}
	if container.SecurityContext.AllowPrivilegeEscalation == nil {
		container.SecurityContext.AllowPrivilegeEscalation = &isFalse
	}
	if container.SecurityContext.ReadOnlyRootFilesystem == nil {
		container.SecurityContext.ReadOnlyRootFilesystem = &isFalse
	}
	if container.SecurityContext.Privileged == nil {
		container.SecurityContext.Privileged = &isFalse
	}

	return container.SecurityContext
}

// FilterOn returns the authorizer handle
func (c *authorizer) FilterOn() api.Filter {
	return api.Filter{
		IgnoreNamespaces: c.config.IgnoreNamespaces,
		Kind:             api.FilterPods,
	}
}

// Name returns the name of the provider
func (c *authorizer) Name() string {
	return Name
}

// New creates and returns a pod authorization implementation
func New(config *Config) (api.Authorize, error) {
	if config == nil {
		config = NewDefaultConfig()
	}
	if err := config.IsValid(); err != nil {
		return nil, err
	}

	providers := make(map[string]podsecuritypolicy.Provider, 0)
	for name, policy := range config.Policies {
		psp := &extensions.PodSecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       policy,
		}

		p, err := podsecuritypolicy.NewSimpleProvider(psp, "", podsecuritypolicy.NewSimpleStrategyFactory())
		if err != nil {
			return nil, fmt.Errorf("unable to load policy '%s', error: '%q'", name, err)
		}
		providers[name] = p
	}

	return &authorizer{
		config:    config,
		providers: providers,
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
