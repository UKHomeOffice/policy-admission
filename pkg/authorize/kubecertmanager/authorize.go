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
	"sort"
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
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
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

	ingress, ok := cx.Object.(*networkingv1beta1.Ingress)
	if !ok {
		return append(errs, field.InternalError(field.NewPath("object"), errors.New("invalid object, expected Ingress")))
	}

	return c.validateIngress(cx, ingress)
}

// validateIngress checks that the ingress's host resolve to the hostname of the cluster's internal or external ingress
func (c *authorizer) validateIngressPointed(cx *api.Context, ingress *networkingv1beta1.Ingress) field.ErrorList {
	var errs field.ErrorList

	// @step: get namespace for this object
	namespace, err := utils.GetCachedNamespace(cx.Client, cx.Cache, ingress.Namespace)
	if err != nil {
		return append(errs, field.InternalError(field.NewPath("namespace"), err))
	}

	enableDNSCheck := namespace.GetAnnotations()[cx.Annotation(EnableDNSCheck)] != "false"

	if enableDNSCheck {
		// @check the dns for the hostnames are pointing to the cname of the external ingress controller
		pointed, err := c.isIngressPointed(ingress)
		if err != nil {
			return append(errs, field.InternalError(field.NewPath("dns validation"), fmt.Errorf("failed to check for dns validation: %s", err)))
		}

		errs = append(errs, pointed...)
	}

	return errs
}

// validateIngress checks the PSG managed ingress complies with policy
func (c *authorizer) validatePsgIngress(cx *api.Context, ingress *networkingv1beta1.Ingress) field.ErrorList {
	var errs field.ErrorList

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

	errs = append(errs, c.validateIngressPointed(cx, ingress)...)

	return errs
}

func (c *authorizer) validateCertManagerIngress(cx *api.Context, ingress *networkingv1beta1.Ingress) field.ErrorList {
	var errs field.ErrorList

	if managers := getCertManagerReferences(ingress); len(managers) != 1 || managers[0] != "cert-manager.io" {
		return nil
	}

	// there is at least one annotation or label prefixed with "cert-manager.io"
	if value, found := ingress.GetAnnotations()["cert-manager.io/enabled"]; !found || value != "true" {
		return append(errs, field.Invalid(field.NewPath("metadata.annotations.cert-manager.io/enabled"), "", "cert-manager.io annotations or labels are present, but annotation cert-manager.io/enabled: \"true\" is missing"))
	}

	ingressValueValid := false
	ingressValue, ingressFound := ingress.GetAnnotations()["kubernetes.io/ingress.class"]
	if ingressFound {
		solverValue, solverFound := ingress.GetLabels()["cert-manager.io/solver"]
		if ingressValue == "nginx-internal" {
			ingressValueValid = true
			if !solverFound || solverValue != "route53" {
				errs = append(errs, field.Invalid(field.NewPath("metadata.labels.cert-manager.io/solver"), solverValue, "nginx-internal has been specified as an annotation for kubernetes.io/ingress.class but label cert-manager.io/solver is missing or not set to route53"))
			}

			errs = append(errs, c.isHostedInternally(ingress)...)
			errs = append(errs, c.validateIngressPointed(cx, ingress)...)
		} else if ingressValue == "nginx-external" {
			ingressValueValid = true
			if solverFound && solverValue != "http01" && solverValue != "route53" {
				errs = append(errs, field.Invalid(field.NewPath("metadata.labels.cert-manager.io/solver"), solverValue, "nginx-external has been specified as an annotation for kubernetes.io/ingress.class but label cert-manager.io/solver has an invalid value: expecting http01, route53 or no solver annotation"))
			}

			errs = append(errs, c.validateIngressPointed(cx, ingress)...)
		}
	}

	if !ingressValueValid {
		errs = append(errs, field.Invalid(field.NewPath("metadata.annotations.kubernetes.io/ingress.class"), ingressValue, "annotation kubernetes.io/ingress.class is missing; please specify a value of either nginx-internal or nginx-external"))
	}

	for tlsIdx, tls := range ingress.Spec.TLS {
		if len(tls.Hosts) > 0 {
			if len(tls.Hosts[0]) > 63 {
				errs = append(errs, field.Invalid(field.NewPath(fmt.Sprintf("spec.tls[%v].hosts[0]", tlsIdx)), tls.Hosts[0], "commonName in certificates should be no more than 63 characters (but additional hosts can be); look at https://ukhomeoffice.github.io/application-container-platform/how-to-docs/cert-manager.html for a work-around allowing you to specify a long host name"))
			}
		}
	}

	if solverValue, solverFound := ingress.GetLabels()["cert-manager.io/solver"]; solverFound && solverValue == "route53" {
		if tlsAcmeValue, tlsAcmeFound := ingress.GetAnnotations()["kubernetes.io/tls-acme"]; tlsAcmeFound && tlsAcmeValue == "true" {
			errs = append(errs, field.Invalid(field.NewPath("metadata.annotations.kubernetes.io/tls-acme"), tlsAcmeValue, "you have specified route53 as the cert-manager solver to use; please remove the kubernetes.io/tls-acme annotation"))
		}
	}

	return errs
}

// getCertManagerReferences returns a map of the certificate managers present from a labels or annotations map
func getCertManagerReferencesFromKeyMap(aMap map[string]string) map[string]bool {
	certManagerReferences := map[string]bool{}

	for k := range aMap {
		if strings.HasPrefix(k, "stable.k8s.psg.io/kcm") {
			certManagerReferences["stable.k8s.psg.io/kcm"] = true
		} else if strings.HasPrefix(k, "certmanager.k8s.io") {
			certManagerReferences["certmanager.k8s.io"] = true
		} else if strings.HasPrefix(k, "cert-manager.io") {
			certManagerReferences["cert-manager.io"] = true
		}
	}

	return certManagerReferences
}

// getCertManagerReferences returns a list of certificate managers mentioned in the ingress
func getCertManagerReferences(ingress *networkingv1beta1.Ingress) []string {
	var allManagers []string

	allReferences := getCertManagerReferencesFromKeyMap(ingress.GetLabels())
	annotationsReferences := getCertManagerReferencesFromKeyMap(ingress.GetAnnotations())

	// merge the 2 maps
	for k, v := range annotationsReferences {
		allReferences[k] = v
	}

	// get the certificate managers list
	for k := range allReferences {
		allManagers = append(allManagers, k)
	}

	sort.Strings(allManagers)

	return allManagers
}

func (c *authorizer) validateSingleCertificateManagerIngress(ingress *networkingv1beta1.Ingress) field.ErrorList {
	var errs field.ErrorList

	certManagerReferenced := getCertManagerReferences(ingress)

	if len(certManagerReferenced) > 1 {
		errs = append(errs, field.Invalid(field.NewPath("metadata.annotations"), "", fmt.Sprintf("this ingress should be managed by a single certificate manager; found prefixes %v in annotations or labels; please use only one of those prefix types and ideally migrate to cert-manager.io", certManagerReferenced)))
	}

	return errs
}

// validateIngress checks the the ingress complies with policy
func (c *authorizer) validateIngress(cx *api.Context, ingress *networkingv1beta1.Ingress) field.ErrorList {
	var errs field.ErrorList

	// @step: if annotations or labels for different certificate managers have been specified, complain and stop here
	if errs = c.validateSingleCertificateManagerIngress(ingress); errs != nil {
		return errs
	}

	// @check this ingress for psg kube-cert-manager errors
	errs = c.validatePsgIngress(cx, ingress)

	// @check this ingress for JetStack's cert-manager.io (v0.11+) errors
	errs = append(c.validateCertManagerIngress(cx, ingress), errs...)

	return errs
}

// isHostedInternally checks the domain is hosted by us - i.e. within a zone we control
func (c *authorizer) isHostedInternally(ingress *networkingv1beta1.Ingress) field.ErrorList {
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

// isIngressPointed is responsible for checking the dns hostname is pointed to eiher external or internal ingress
// depending on the ingress class
func (c *authorizer) isIngressPointed(ingress *networkingv1beta1.Ingress) (field.ErrorList, error) {
	var errs field.ErrorList
	var ingressType string

	var expectedHostName string
	if value, found := ingress.GetAnnotations()["kubernetes.io/ingress.class"]; found && value == "nginx-internal" {
		expectedHostName = c.config.InternalIngressHostname
		ingressType = "internal"
	} else {
		expectedHostName = c.config.ExternalIngressHostname
		ingressType = "external"
	}

	for i, x := range ingress.Spec.Rules {
		if cname, err := c.resolve.GetCNAME(x.Host); err != nil {
			return errs, err
		} else if cname != expectedHostName {
			return append(errs, field.Invalid(field.NewPath("spec").Child("rules").Index(i).Child("host"), x.Host,
				fmt.Sprintf("the hostname: %s is not pointed to the %s ingress dns name %s", x.Host, ingressType, expectedHostName))), nil
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
		IgnoreNamespaces:      c.config.IgnoreNamespaces,
		IgnoreNamespaceLabels: c.config.IgnoreNamespaceLabels,
		Kind:                  api.FilterIngresses,
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
