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

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"github.com/labstack/echo"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	admission "k8s.io/api/admission/v1alpha1"
	extensions "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	core "k8s.io/kubernetes/pkg/api"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
}

var (
	// namespaceExpiry is the default time we will expiry resources
	namespaceExpiry = time.Duration(60 * time.Second)
	// resourceTimeout is the default time we willing to wait for resources from api
	resourceTimeout = time.Duration(2 * time.Second)
	// ErrNotSupported indicated we do not support this object type
	ErrNotSupported = errors.New("unsupported object type")
)

// AdmitStatus is the used to hold the result of review
type AdmitStatus struct {
	// Kind is the kind of object
	Kind string
	// Object is the review object
	Object metav1.Object
	// Detail is the reason it was denied if any
	Detail string
}

// admit is responsible for applying the policy on the incoming request
func (c *Admission) admit(review *admission.AdmissionReview) error {
	admit, status, err := c.handleAdmissionReview(review)
	if err != nil {
		log.WithFields(log.Fields{
			"error":     err.Error(),
			"namespace": review.Spec.Namespace,
		}).Errorf("unable to handle admission review")

		return err
	}

	if !admit {
		log.WithFields(log.Fields{
			"error":     status.Detail,
			"namespace": review.Spec.Namespace,
			"name":      status.Object.GetGenerateName(),
		}).Warn("authorization for object execution denied")

		review.Status.Allowed = false
		review.Status.Result = &metav1.Status{
			Code:    http.StatusForbidden,
			Message: status.Detail,
			Reason:  metav1.StatusReasonForbidden,
			Status:  metav1.StatusFailure,
		}

		// @step: log the kubernetes event if required
		if c.config.EnableEvents {
			c.createPodDeniedEvent(c.client, status.Object, status.Detail)
		}

		return nil
	}
	review.Status.Allowed = true

	log.WithFields(log.Fields{
		"namespace": status.Object.GetNamespace(),
		"status":    status.Object.GetGenerateName(),
	}).Info("object is authorized for execution")

	return nil
}

// handleAdmissionReview is responsible for handling the admission review
func (c *Admission) handleAdmissionReview(review *admission.AdmissionReview) (bool, AdmitStatus, error) {
	var status AdmitStatus
	var object metav1.Object

	kind := review.Spec.Kind.Kind

	// @check if the review is for something we can process
	object, err := c.getResourceForReview(kind, review)
	if err != nil {
		return true, status, nil
	}
	status.Object = object

	// @step: iterate the authorizers and fail on first refusal
	// @TODO: run the authorizers in parallel on multi-cores
	for _, provider := range c.providers {
		// @check if this authorizer is listening to this type
		if provider.FilterOn().Kind != kind {
			continue
		}
		// @check if the authorizer is ignoring this namespace
		if utils.Contained(review.Spec.Namespace, provider.FilterOn().IgnoreNamespaces) {
			log.WithFields(log.Fields{
				"name":      object.GetName(),
				"namespace": review.Spec.Namespace,
				"provider":  provider.Name(),
			}).Warn("provider ignoring namespace")
			continue
		}
		object.SetNamespace(review.Spec.Namespace)

		if errs := provider.Admit(c.client, c.resourceCache, object); len(errs) > 0 {
			var reasons []string
			for _, x := range errs {
				reasons = append(reasons, fmt.Sprintf("%s=%v : %s", x.Field, x.BadValue, x.Detail))
			}
			status.Detail = strings.Join(reasons, ",")

			return false, status, nil
		}
	}

	return true, status, nil
}

// getResourceForReview checks the kind of resource and decodes into the specific type
func (c *Admission) getResourceForReview(kind string, review *admission.AdmissionReview) (metav1.Object, error) {
	var object metav1.Object

	switch kind {
	case api.FilterServices:
		object = &core.Service{}
	case api.FilterPods:
		object = &core.Pod{}
	case api.FilterIngresses:
		object = &extensions.Ingress{}
	case api.FilterNamespace:
		object = &extensions.Ingress{}
	default:
		return nil, ErrNotSupported
	}

	// @step: decode the object into a object specification
	if err := json.Unmarshal(review.Spec.Object.Raw, object); err != nil {
		return nil, err
	}

	return object, nil
}

// Start is repsonsible for starting the service up
func (c *Admission) Start() error {
	client, err := c.getKubernetesClient()
	if err != nil {
		return err
	}
	c.client = client

	go func() {
		if err := c.engine.StartServer(c.server); err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Fatal("unable to create the http server")
		}
	}()

	return nil
}

// New creates and returns a new admission Admission
func New(config *Config, providers []api.Authorize) (*Admission, error) {
	if len(providers) <= 0 {
		return nil, errors.New("no authorizers defined")
	}

	log.Infof("policy admission controller, listen: %s", config.Listen)
	for _, x := range providers {
		log.Infof("enabling the authorizer: %s, ignored: %s, filter: %s", x.Name(),
			strings.Join(x.FilterOn().IgnoreNamespaces, ","), x.FilterOn().Kind)
	}

	c := &Admission{
		config:        config,
		providers:     providers,
		resourceCache: cache.New(1*time.Minute, 5*time.Minute),
	}

	// @step: create the http router
	engine := echo.New()
	engine.HideBanner = true
	//engine.Use(middleware.Recover())
	engine.POST("/", c.admitHandler)
	engine.GET("/health", c.healthHandler)

	// @step: create the http server
	server, err := utils.NewHTTPServer(config.Listen, config.TLSCert, config.TLSKey)
	if err != nil {
		return nil, err
	}
	c.engine = engine
	c.server = server
	c.server.Handler = c.engine

	return c, nil
}
