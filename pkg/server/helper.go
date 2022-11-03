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
	"encoding/json"

	"github.com/UKHomeOffice/policy-admission/pkg/api"

	admission "k8s.io/api/admission/v1"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// decodeObject checks the kind of resource and decodes into the specific type
func decodeObject(kind string, review *admission.AdmissionReview) (metav1.Object, error) {
	var object metav1.Object

	switch kind {
	case api.FilterDeployments:
		object = &apps.Deployment{}
	case api.FilterIngresses:
		object = &networkingv1.Ingress{}
	case api.FilterNamespace:
		object = &core.Namespace{}
	case api.FilterNetworkPolicy:
		object = &networkingv1.NetworkPolicy{}
	case api.FilterPods:
		object = &core.Pod{}
	case api.FilterReplicaSet:
		object = &apps.ReplicaSet{}
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
