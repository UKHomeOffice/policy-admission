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
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/route53/route53iface"
	"k8s.io/apimachinery/pkg/util/validation/field"
	extensions "k8s.io/kubernetes/pkg/apis/extensions"
)

// isHosted checks the domain is hosted by us
func isHosted(ingress *extensions.Ingress, domains []string) bool {
	for _, x := range ingress.Spec.Rules {
		for _, dns := range domains {
			if strings.HasSuffix(x.Host, dns) {
				return true
			}
		}
	}

	return false
}

// getAWSHostedDomains returns a list of hosted domains or an error
func getAWSHostedDomains(client route53iface.Route53API) ([]string, error) {
	resp, err := client.ListHostedZones(&route53.ListHostedZonesInput{})
	if err != nil {
		return []string{}, err
	}

	var list []string
	for _, x := range resp.HostedZones {
		list = append(list, aws.StringValue(x.Name))
	}

	return list, nil
}

// isIngressPointed is responisble for checking the dns hostname is pointed to the external ingress
func isIngressPointed(dns resolver, hostname string, ingress *extensions.Ingress) (field.ErrorList, error) {
	var errs field.ErrorList

	for i, x := range ingress.Spec.Rules {
		if cname, err := dns.GetCNAME(x.Host); err != nil {
			return errs, err
		} else if cname != hostname {
			return append(errs, field.Invalid(field.NewPath("spec").Child("rules").Index(i).Child("host"), x.Host,
				fmt.Sprintf("the hostname: %s is not pointed to the external ingress dns name %s", x.Host, hostname))), nil
		}
	}

	return errs, nil
}
