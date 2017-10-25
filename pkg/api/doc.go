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

package api

import (
	"github.com/patrickmn/go-cache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
)

var (
	// FilterAdmission indicates you want to see the admission
	FilterAdmission = "Admission"
	// FilterIngresses indicates you want to see pods
	FilterIngresses = "Ingress"
	// FilterNamespace is a Namespace
	FilterNamespace = "Namespace"
	// FilterPods indicates you want to see pods
	FilterPods = "Pod"
	// FilterServices indicates we are looking at services
	FilterServices = "Service"
)

// Authorize is the interface for a authorizer
type Authorize interface {
	// Admit makes a decision on the pod acceptance
	Admit(kubernetes.Interface, *cache.Cache, metav1.Object) field.ErrorList
	// Name is the name of the authorizer
	Name() string
	// FilterOn return the filter for the authorizer
	FilterOn() Filter
}

// Filter defines what the authorizer is looking to filter on, or listen to
type Filter struct {
	// Kind is the object kind we looking filter on i.e. (pods, ingresses etc)
	Kind string
	// IgnoreNamespace indicates you wish to ignore the following namespace
	IgnoreNamespaces []string
	// IgnoreOnFailure indicates you wish to ignore the provider on internal errors
	IgnoreOnFailure bool
}
