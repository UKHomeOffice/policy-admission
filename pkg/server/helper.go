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

package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"
	log "github.com/sirupsen/logrus"

	admission "k8s.io/api/admission/v1beta1"
	admissionregistration "k8s.io/api/admissionregistration/v1beta1"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// resourceVersion is a internal type used to dedup the resources
type resourceVersion struct {
	Group     string
	Version   string
	Resources []string
}

// registerAdmissionController is responsible for attempting to register the controller with the API
func (c *Admission) registerAdmissionController(hook *admissionregistration.ValidatingWebhookConfiguration) error {
	log.Info("attempting to register the admission controller with kube api")

	return utils.Retry(3, 2*time.Second, func() error {
		resp, err := c.client.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().List(metav1.ListOptions{})
		if err != nil {
			return err
		}
		var found bool
		for _, x := range resp.Items {
			if x.GetName() == c.config.ControllerName {
				found = true
				break
			}
		}
		if !found {
			_, err = c.client.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Create(hook)
		} else {
			_, err = c.client.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Update(hook)
		}

		return err
	})
}

// createAdmissionWebhook is responsible is creating a admission webhook from the providers
func (c *Admission) createAdmissionWebhook() (*admissionregistration.ValidatingWebhookConfiguration, error) {
	var cabundle []byte
	var err error

	// @step: add the cabundle if specified
	if c.config.CertificateBundlePath != "" {
		cabundle, err = ioutil.ReadFile(c.config.CertificateBundlePath)
		if err != nil {
			return nil, err
		}
	}

	onfailure := admissionregistration.Ignore
	if c.config.FailurePolicy == "Fail" {
		onfailure = admissionregistration.Fail
	}

	// @step: construct the webhook for the service
	webhook := &admissionregistration.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: c.config.ControllerName,
		},
		Webhooks: []admissionregistration.Webhook{
			{
				Name: c.config.ControllerName,
				ClientConfig: admissionregistration.WebhookClientConfig{
					CABundle: []byte(base64.StdEncoding.EncodeToString(cabundle)),
					Service: &admissionregistration.ServiceReference{
						Namespace: c.config.Namespace,
						Name:      c.config.ServiceName,
					},
				},
				FailurePolicy: &onfailure,
				Rules:         []admissionregistration.RuleWithOperations{},
			},
		},
	}

	// @step: work out which resources we are listening to
	versions := make(map[string]*resourceVersion, 0)
	for _, x := range c.providers {
		// @step: get a api version key
		hash := fmt.Sprintf("%s/%s",
			utils.DefaultTo(x.FilterOn().Group, "*"),
			utils.DefaultTo(x.FilterOn().Version, "*"))

		// @step: check if the group/api exists and add the resource
		if v, found := versions[hash]; !found {
			versions[hash] = &resourceVersion{
				Group:     utils.DefaultTo(x.FilterOn().Group, "*"),
				Version:   utils.DefaultTo(x.FilterOn().Version, "*"),
				Resources: []string{x.FilterOn().Kind},
			}
		} else {
			// @check if the resource has already been added, else add it
			if !utils.Contained(x.FilterOn().Kind, v.Resources) {
				v.Resources = append(v.Resources, x.FilterOn().Kind)
			}
		}
	}

	// @step: iterate the versions and add the rules
	for _, v := range versions {
		webhook.Webhooks[0].Rules = append(webhook.Webhooks[0].Rules, admissionregistration.RuleWithOperations{
			Operations: []admissionregistration.OperationType{
				admissionregistration.Create,
				admissionregistration.Update,
			},
			Rule: admissionregistration.Rule{
				APIGroups:   []string{v.Group},
				APIVersions: []string{v.Version},
				Resources:   v.Resources,
			},
		})
	}

	return webhook, nil
}

// decodeObject checks the kind of resource and decodes into the specific type
func decodeObject(kind string, review *admission.AdmissionReview) (metav1.Object, error) {
	var object metav1.Object

	switch kind {
	case api.FilterDeployments:
		object = &extensions.Deployment{}
	case api.FilterIngresses:
		object = &extensions.Ingress{}
	case api.FilterNamespace:
		object = &core.Namespace{}
	case api.FilterNetworkPolicy:
		object = &extensions.NetworkPolicy{}
	case api.FilterPods:
		object = &core.Pod{}
	case api.FilterReplicaSet:
		object = &extensions.ReplicaSet{}
	case api.FilterReplicationControllers:
		object = &core.ReplicationController{}
	case api.FilterServices:
		object = &core.Service{}
	case api.FilterStatefulSet:
		object = &apps.StatefulSet{}
	default:
		object = &unstructured.Unstructured{}
	}

	// @step: decode the object into a object specification
	if err := json.Unmarshal(review.Request.Object.Raw, object); err != nil {
		return nil, err
	}

	return object, nil
}
