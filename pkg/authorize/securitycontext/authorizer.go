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
	core "k8s.io/kubernetes/pkg/apis/core"
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

	// @step: select the policy to apply against
	if override, found := c.config.defaultPolicy(pod.Namespace); found {
		name = override
	}

	// @step: get namespace for this object
	namespace, err := utils.GetCachedNamespace(client, mcache, pod.Namespace)
	if err != nil {
		return append(errs, field.InternalError(field.NewPath(pod.Namespace), err))
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

	policy := c.config.Policies[name]
	// @check if the init container are valid agains the policy
	errs = append(errs, c.validateContainers(field.NewPath("spec", "initContainers"), &policy, provider, pod, pod.Spec.InitContainers)...)
	// @check the main containers to not invalidate the psp
	errs = append(errs, c.validateContainers(field.NewPath("spec", "containers"), &policy, provider, pod, pod.Spec.Containers)...)

	return errs
}

// validatePod is responsible for valudating the pod spec against the psp
func (c *authorizer) validatePod(provider podsecuritypolicy.Provider, pod *core.Pod) field.ErrorList {
	if err := provider.DefaultPodSecurityContext(pod); err != nil {
		return field.ErrorList{{Type: field.ErrorTypeInternal, Detail: err.Error()}}
	}

	return provider.ValidatePod(pod, field.NewPath("spec", "securityContext"))
}

// validateContainers is responisble for iterating the containers and validating against the policy
func (c *authorizer) validateContainers(path *field.Path, policy *extensions.PodSecurityPolicySpec, provider podsecuritypolicy.Provider, pod *core.Pod, containers []core.Container) field.ErrorList {

	var errs field.ErrorList

	noRoot := policy.RunAsUser.Rule == extensions.RunAsUserStrategyMustRunAsNonRoot
	for i := range containers {
		containers[i].SecurityContext = assignSecurityContext(pod, &containers[i])

		if err := provider.DefaultContainerSecurityContext(pod, &containers[i]); err != nil {
			return field.ErrorList{{Type: field.ErrorTypeInternal, Detail: err.Error()}}
		}
		errs = append(errs, provider.ValidateContainerSecurityContext(pod, &containers[i], path.Index(i))...)

		if !c.config.EnableSubPaths {
			errs = append(errs, validateContainerSubPaths(path.Index(i), &containers[i])...)
		}
		if noRoot {
			errs = append(errs, validateRunAsNonRoot(path.Root(), path.Index(i), pod, &containers[i])...)
		}
	}

	return errs
}

// validateRunAsNonRoot adding a manual check for the non-root i can't get the frigging psp to work for me
func validateRunAsNonRoot(podPath, containerPath *field.Path, pod *core.Pod, container *core.Container) field.ErrorList {
	var errs field.ErrorList

	// @step: if the pod security context is non-root we can skip
	if pod.Spec.SecurityContext == nil && container.SecurityContext == nil {
		return append(errs, field.Required(podPath.Child("securityContext"), "no securityContext set for the pod or container"))
	}

	var nonroot bool
	if pod.Spec.SecurityContext != nil {
		sc := pod.Spec.SecurityContext

		if sc.RunAsUser != nil && *sc.RunAsUser == 0 {
			errs = append(errs, field.Invalid(podPath.Child("securityContext").Child("runAsUser"), false, "runAsUser cannot be root"))
		}

		nonroot = len(errs) <= 0
	}

	// @step: we need to check the container itself
	sc := container.SecurityContext
	if !nonroot && sc == nil {
		return append(errs, field.Required(containerPath.Child("securityContext"), "no security context for container and RunAsNonRoot is required"))
	}

	if nonroot {
		// @here the pod has specified a non-root run either by runNonRoot or runAsUser
		if sc.RunAsNonRoot != nil && *sc.RunAsNonRoot == false {
			return append(errs, field.Invalid(containerPath.Child("securityContext").Child("runAsNonRoot"), false, "must run as nonroot"))
		}
		if sc.RunAsNonRoot != nil && *sc.RunAsNonRoot == false {
			errs = append(errs, field.Invalid(containerPath.Child("securityContext").Child("runAsNonRoot"), false, "runAsNonRoot cannot be false"))
		}
		/*
			if sc.RunAsUser != nil && *sc.RunAsUser == 0 {
				return append(errs, field.Invalid(containerPath.Child("securityContext").Child("runAsUser"), 0, "runAsUser cannot be root"))
			}
		*/
	} else {
		// @here the pod is can potientially be running as root, lets check the container overrides it
		if sc.RunAsNonRoot == nil && sc.RunAsUser == nil {
			return append(errs, field.Required(containerPath.Child("securityContext"), "neither runAsUser or runAsNonRoot is set and the pod is set run as root"))
		}
		if sc.RunAsNonRoot != nil && *sc.RunAsNonRoot == false {
			errs = append(errs, field.Invalid(containerPath.Child("securityContext").Child("runAsNonRoot"), false, "runAsNonRoot cannot be false"))
		}
		if sc.RunAsUser != nil && *sc.RunAsUser == 0 {
			errs = append(errs, field.Invalid(containerPath.Child("securityContext").Child("runAsUser"), 0, "runAsUser cannout be root"))
		}
	}

	return errs
}

// validateContainerSubPaths ensures the container has not subpaths in the volumes
func validateContainerSubPaths(path *field.Path, container *core.Container) field.ErrorList {
	var errs field.ErrorList
	for i, x := range container.VolumeMounts {
		if x.SubPath != "" {
			errs = append(errs, field.Invalid(path.Child("volumeMounts").Index(i).Child("subPath"), x.SubPath, "subpath in volumeMount is not permitted"))
		}
	}

	return errs
}

// assignSecurityContext is responsible for assigning some defaults
func assignSecurityContext(pod *core.Pod, container *core.Container) *core.SecurityContext {
	isFalse := false
	if container.SecurityContext == nil {
		container.SecurityContext = &core.SecurityContext{}
	}
	if container.SecurityContext.RunAsNonRoot == nil {
		container.SecurityContext.RunAsNonRoot = &isFalse
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
