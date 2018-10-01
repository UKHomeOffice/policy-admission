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
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/route53/route53iface"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// resolver is purely wrapped for conveience of testing
type resolver interface {
	GetCNAME(string) (string, error)
}

const cachedDomains = "domains"

type authorizer struct {
	// config the configuration for the service
	config *Config
	// resolve is a dns resolver
	resolve resolver
	// client is the route53 client
	client route53iface.Route53API
	// cached is a small in-memory cache
	cached *cache.Cache
}

// Admit is responsible for authorizing the ingress for kube-cert-manager
func (c *authorizer) Admit(_ context.Context, cx *api.Context) field.ErrorList {
	var errs field.ErrorList

	ingress, ok := cx.Object.(*extensions.Ingress)
	if !ok {
		return append(errs, field.InternalError(field.NewPath("object"), errors.New("invalid object, expected Ingress")))
	}

	return c.validateIngress(ingress)
}

// validateIngress checks the the image complys with policy
func (c *authorizer) validateIngress(ingress *extensions.Ingress) field.ErrorList {
	var errs field.ErrorList

	// @check is this ingress has kube-cert-manager is enabled
	if value, found := ingress.GetLabels()["stable.k8s.psg.io/kcm.class"]; !found || value != "default" {
		return errs
	}

	// @check if the domain is not within the internally hosts domain i.e. the provider is missing or set to dns
	if value, found := ingress.GetAnnotations()["stable.k8s.psg.io/kcm.provider"]; !found || value == "dns" {
		return c.isHostedInternally(ingress)
	}

	// @logic: else the domain it's requesting is outside of the internally hosted domain/s

	label := "stable.k8s.psg.io/kcm.provider"
	class := "http"
	annontations := ingress.GetAnnotations()

	// @check we have http challenge enabled
	if value, found := annontations["stable.k8s.psg.io/kcm.provider"]; !found {
		return append(errs, field.Invalid(field.NewPath("annotations").Key(label), value,
			"one or more domains in the ingress are externally hosted, you must use a http challenge"))
	} else if value != "http" {
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

// isHostedInternally checks the domain is hosted by us - i.e. within a zone we control
func (c *authorizer) isHostedInternally(ingress *extensions.Ingress) field.ErrorList {
	var errs field.ErrorList

	// @step: retrieve the list to domains we are hosting
	domains, err := c.getHostedDomains()
	if err != nil {
		return append(errs, field.InternalError(field.NewPath(""), fmt.Errorf("unable to retrieve internally hosted domains: %s", err)))
	}

	log.WithFields(log.Fields{
		"domains": strings.Join(domains, ","),
	}).Debug("checking ingress agains the following permitted domains")

	// @step: iterate the list of and check for a match
	for i, x := range ingress.Spec.Rules {
		if x.Host == "" {
			continue
		}

		var found bool

		// @step: check if the domain is hosted is permitted
		for _, domain := range domains {
			if domain == "" {
				continue
			}
			if strings.HasSuffix(x.Host, domain) {
				found = true
				break
			}
		}

		// @step: if not found, alert the domains as invalid
		if !found {
			path := field.NewPath("spec").Child("rules").Index(i).Child("host")
			errs = append(errs, field.Invalid(path, x.Host, "domain is not hosted internally and thus denied"))
		}
	}

	return errs
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

// getHostedDomains returns a list of hosted domains
func (c *authorizer) getHostedDomains() ([]string, error) {
	var domains []string

	domains = append(domains, c.config.HostedDomains...)

	// @check is no access or secret key we default to hostdomains only
	if !c.config.UseRoute53Check() {
		return domains, nil
	}

	// @check the we don't have the value in the cache
	if hosts, found := c.cached.Get(cachedDomains); !found {
		err := utils.Retry(3, 100*time.Millisecond, func() error {
			log.Debug("attempting to request the hosted domains from route53")

			list, err := getRoute53HostedDomains(c.client)
			if err != nil {
				return err
			}

			log.WithFields(log.Fields{
				"domains": strings.Join(list, ","),
			}).Debug("found the following domains hosted in the account")

			domains = append(domains, list...)

			c.cached.Set(cachedDomains, list, 3*time.Minute)

			return nil
		})
		if err != nil {
			return []string{}, err
		}
	} else {
		domains = append(domains, hosts.([]string)...)
	}

	return domains, nil
}

// Name is the authorizer
func (c *authorizer) Name() string {
	return Name
}

// FilterOn returns the authorizer handle
func (c *authorizer) FilterOn() *api.Filter {
	return &api.Filter{
		IgnoreNamespaces: c.config.IgnoreNamespaces,
		Kind:             api.FilterIngresses,
	}
}

// New creates and returns a letsencrypt authorizer
func New(config *Config) (api.Authorize, error) {
	if config == nil {
		config = NewDefaultConfig()
	}

	svc := &authorizer{
		cached:  cache.New(10*time.Minute, 1*time.Minute),
		config:  config,
		resolve: &resolverImp{},
	}

	if config.UseRoute53Check() {
		svc.client = route53.New(session.Must(
			session.NewSession(&aws.Config{
				Credentials: credentials.NewStaticCredentials(os.Getenv(kubeCertAccessID), os.Getenv(kubeCertSecretID), ""),
				Region:      aws.String("AWS_DEFAULT_REGION"),
			})))
	}

	return svc, nil
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
