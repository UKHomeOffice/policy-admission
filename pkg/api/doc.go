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
	"context"
	"path/filepath"

	"github.com/patrickmn/go-cache"
	admission "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
)

// AdmissionControllerName is the name admission controller
const AdmissionControllerName = "policy-admission"

var (
	// FilterAll indicates you want to recieved all registered objects
	FilterAll = "All"
	// FilterAdmission indicates you want to see the admission
	FilterAdmission = "Admission"
	// FilterDeployments indicates you want to see the deployments
	FilterDeployments = "Deployment"
	// FilterIngresses indicates you want to see pods
	FilterIngresses = "Ingress"
	// FilterNamespace is a Namespace
	FilterNamespace = "Namespace"
	// FilterNetworkPolicy indicates a network policy
	FilterNetworkPolicy = "NetworkPolicy"
	// FilterPods indicates you want to see pods
	FilterPods = "Pod"
	// FilterReplicaSet indicates replicasets
	FilterReplicaSet = "ReplicaSet"
	// FilterReplicationControllers indicates we listen to rc
	FilterReplicationControllers = "ReplicationControllers"
	// FilterServices indicates we are looking at services
	FilterServices = "Service"
	// FilterStatefulSet indicates are filter on statefulset
	FilterStatefulSet = "StatefulSet"
)

// Sink is the implementation for a events consumer
type Sink interface {
	// Send is responsible is sending messages
	Send(*Event) error
}

// Event is a denial event
type Event struct {
	// Detail is the detail about the error
	Detail string
	// Provider is the provider whom denied it
	Provider string
	// Object is the decoded object
	Object metav1.Object
	// Review is a reference to the review
	Review *admission.AdmissionRequest
}

// Context is context of the request
type Context struct {
	// Cache is a resource cache
	Cache *cache.Cache
	// Client is a kubernetes client
	Client kubernetes.Interface
	// Object is the object we are validating
	Object metav1.Object
	// Prefix the controller prefix
	Prefix string
}

// Annotation returns a annotation name
func (c *Context) Annotation(names ...string) string {
	paths := []string{c.Prefix}
	paths = append(paths, names...)

	return filepath.Join(paths...)
}

// Authorize is the interface for a authorizer
type Authorize interface {
	// Admit makes a decision on the pod acceptance
	Admit(context.Context, *Context) field.ErrorList
	// Name is the name of the authorizer
	Name() string
	// FilterOn return the filter for the authorizer
	FilterOn() Filter
	// Stop is called when the authorizer is being replaced
	Stop() error
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
