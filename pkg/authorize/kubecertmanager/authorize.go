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

package kubecertmanager

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"github.com/patrickmn/go-cache"
	extensions "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
)

// resolver is purely wrapped for conveience of testing
type resolver interface {
	GetCNAME(string) (string, error)
}

type authorizer struct {
	// config the configuration for the service
	config *Config
	// resolve is a dns resolver
	resolve resolver
}

// Admit is responsible for authorizing the ingress for kube-cert-manager
func (c *authorizer) Admit(client kubernetes.Interface, mcache *cache.Cache, object metav1.Object) field.ErrorList {
	var errs field.ErrorList

	ingress, ok := object.(*extensions.Ingress)
	if !ok {
		return append(errs, field.InternalError(field.NewPath("object"), errors.New("invalid object, expected Ingress")))
	}

	// @step: validate the ingress is ok for kube-cert-manager
	return c.validateIngress(ingress)
}

// validateIngress checks the the image complys with policy
func (c *authorizer) validateIngress(ingress *extensions.Ingress) field.ErrorList {
	var errs field.ErrorList

	label := "stable.k8s.psg.io/kcm.class"
	class := "default"

	// @check is this ingress has kube-cert-manager is enabled
	if value, found := ingress.GetLabels()[label]; !found || value != class {
		return errs
	}

	// @check if the domain is not within the internally hosts domain
	if hosted := c.isHosted(ingress); hosted {
		// @check we are not trying to use a http challenge
		return errs
	}

	// @logic: else the domain it's requesting is outside of the internally hosted domain/s

	label = "stable.k8s.psg.io/kcm.provider"
	class = "http"
	annontations := ingress.GetAnnotations()

	// @check we have http challenge enabled
	if value, found := annontations[label]; !found {
		return append(errs, field.Invalid(field.NewPath("annotations").Key(label), value,
			"one or more domains in the ingress are externally hosted, you must use a http challenge"))
	} else if value != class {
		return append(errs, field.Invalid(field.NewPath("annotations").Key(label), value,
			fmt.Sprintf("invalid kube-cert-manager provider type: %s, expected: %s", value, class)))
	}

	// @check the nginx is external
	label = "kubernetes.io/ingress.class"
	class = "nginx-external"

	if value, found := annontations[label]; !found {
		return append(errs, field.Invalid(field.NewPath("annotations").Key(label), "",
			"the ingress does not specify a nginx class in annotations"))
	} else if value != class {
		return append(errs, field.Invalid(field.NewPath("annotations").Key(label), value,
			fmt.Sprintf("invalid kube-cert-manager provider, expected '%s' for a http challenge", class)))
	}

	// @check the dns for the hostnames are pointing to the cname of the external ingress controller
	pointed, err := c.isIngressPointed(ingress)
	if err != nil {
		return append(errs, field.InternalError(field.NewPath("dns validation"), fmt.Errorf("failed to check for dns validation: %s", err)))
	}

	errs = append(errs, pointed...)

	return errs
}

// isHosted checks the domain is hosted by us
func (c *authorizer) isHosted(ingress *extensions.Ingress) bool {
	for _, x := range ingress.Spec.Rules {
		for _, dns := range c.config.HostedDomains {
			if strings.HasSuffix(x.Host, dns) {
				return true
			}
		}
	}

	return false
}

// isIngressPointed is responisble for checking the dns hostname is pointed to the external ingress
func (c *authorizer) isIngressPointed(ingress *extensions.Ingress) (field.ErrorList, error) {
	var errs field.ErrorList

	for i, x := range ingress.Spec.Rules {
		if cname, err := c.resolve.GetCNAME(x.Host); err != nil {
			return errs, err
		} else if cname != c.config.ExternalIngressHostname {
			return append(errs, field.Invalid(field.NewPath("spec").Child("rules").Index(i).Child("host"), x.Host,
				fmt.Sprintf("the hostname: %s is not pointed to the external ingress dns name %s", x.Host, c.config.ExternalIngressHostname))), nil
		}
	}

	return errs, nil
}

// Name is the authorizer
func (c *authorizer) Name() string {
	return Name
}

// FilterOn returns the authorizer handle
func (c *authorizer) FilterOn() api.Filter {
	return api.Filter{
		IgnoreNamespaces: c.config.IgnoreNamespaces,
		Kind:             api.FilterIngresses,
	}
}

// New creates and returns a letsencrypt authorizer
func New(config *Config) (api.Authorize, error) {
	if config == nil {
		config = NewDefaultConfig()
	}

	return &authorizer{
		config:  config,
		resolve: &resolverImp{},
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

type resolverImp struct{}

func (s *resolverImp) GetCNAME(hostname string) (string, error) {
	return net.LookupCNAME(hostname)
}

// Stop is called when the authorizer is being shutdown
func (c *authorizer) Stop() error {
	return nil
}
