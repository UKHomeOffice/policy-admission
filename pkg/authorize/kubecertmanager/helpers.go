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
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// isHosted checks the domain is hosted by us
func isHosted(ingress *networkingv1.Ingress, domains []string) bool {
	for _, x := range ingress.Spec.Rules {
		for _, dns := range domains {
			if strings.HasSuffix(x.Host, dns) {
				return true
			}
		}
	}

	return false
}

// getRoute53HostedDomains returns a list of hosted domains or an error
func getRoute53HostedDomains(client route53iface.Route53API) ([]string, error) {
    var hostedZones []string
    var marker *string
    for {
        input := &route53.ListHostedZonesInput{
            MaxItems: aws.String("100"),
        }
        if marker != nil {
            input.Marker = marker
        }
        output, err := client.ListHostedZones(input)
        if err != nil {
            return []string{}, err
        }
        for _, x := range output.HostedZones {
            hostedZones = append(hostedZones, strings.TrimSuffix(aws.StringValue(x.Name), "."))
        }
        if output.IsTruncated != nil && *output.IsTruncated {
            marker = output.NextMarker
        } else {
            break
        }
    }
    return hostedZones, nil
}

// isIngressPointed is responisble for checking the dns hostname is pointed to the external ingress
func isIngressPointed(dns resolver, hostname string, ingress *networkingv1.Ingress) (field.ErrorList, error) {
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
