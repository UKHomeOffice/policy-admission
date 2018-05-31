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
	"github.com/UKHomeOffice/policy-admission/pkg/events"
	"github.com/UKHomeOffice/policy-admission/pkg/events/kube"
	"github.com/UKHomeOffice/policy-admission/pkg/events/slack"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	admission "k8s.io/api/admission/v1beta1"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
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

const (
	// The request has been refused
	actionDenied = "deny"
	// The request has been accepted
	actionAccepted = "accept"
	// The request has cause an error
	actionErrored = "error"
)

// admissionResult is the result of a admission review
type admissionResult struct {
	// Allowed is shortcut if the object is permited
	Allowed bool
	// Object is the which was for review
	Object metav1.Object
	// Response is what the admission response should be
	Status *metav1.Status
}

// admit is responsible for applying the policy on the incoming request
func (c *Admission) admit(review *admission.AdmissionReview) error {
	result, err := c.handleAdmissionReview(review)
	if err != nil {
		admissionErrorMetric.Inc()

		if err != ErrNotSupported {
			log.WithFields(log.Fields{
				"error":     err.Error(),
				"name":      review.Request.Name,
				"namespace": review.Request.Namespace,
			}).Errorf("unable to handle admission review")

			return err
		}

		// @else the object was not supported, we permit through but raise a warning
		log.WithFields(log.Fields{
			"group":     review.Request.Kind.Group,
			"kind":      review.Request.Kind.Kind,
			"name":      review.Request.Name,
			"namespace": review.Request.Namespace,
		}).Warn("object kind is not suppported")

		result.Allowed = true
	}

	if !result.Allowed {
		status := result.Status
		// @step: increment the counter
		admissionTotalMetric.WithLabelValues(actionDenied).Inc()

		log.WithFields(log.Fields{
			"error":     status.Message,
			"group":     review.Request.Kind.Group,
			"kind":      review.Request.Kind.Kind,
			"name":      review.Request.Name,
			"namespace": review.Request.Namespace,
			"uid":       review.Request.UserInfo.UID,
			"user":      review.Request.UserInfo.Username,
		}).Warn("authorization for object execution denied")

		review.Response = &admission.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Code:    http.StatusForbidden,
				Message: status.Message,
				Reason:  metav1.StatusReasonForbidden,
				Status:  metav1.StatusFailure,
			},
		}

		// @step: log the denial is required
		go func() {
			if err := c.events.Send(result.Object, status.Message); err != nil {
				log.WithFields(log.Fields{
					"error": err.Error(),
				}).Error("failed to publish event")

				admissionErrorMetric.Inc()
			}
		}()

		return nil
	}
	admissionTotalMetric.WithLabelValues(actionAccepted).Inc()

	review.Response = &admission.AdmissionResponse{Allowed: true}

	log.WithFields(log.Fields{
		"group":     review.Request.Kind.Group,
		"kind":      review.Request.Kind.Kind,
		"name":      review.Request.Name,
		"namespace": review.Request.Namespace,
		"user":      review.Request.UserInfo.Username,
		"uid":       review.Request.UserInfo.UID,
	}).Info("object has been authorized for execution")

	return nil
}

// handleAdmissionReview is responsible for handling the review and returning a result
func (c *Admission) handleAdmissionReview(review *admission.AdmissionReview) (*admissionResult, error) {
	var object metav1.Object

	// @check if the review is for something we can process
	kind := review.Request.Kind.Kind
	object, err := c.getResourceForReview(kind, review)
	if err != nil {
		return nil, err
	}

	result := &admissionResult{
		Allowed: true,
		Object:  object,
		Status:  &metav1.Status{},
	}
	status := result.Status

	// @step: iterate the authorizers and fail on first refusal
	for i, provider := range c.providers {

		// @check if this authorizer is listening to this type
		if provider.FilterOn().Kind != api.FilterAll && provider.FilterOn().Kind != kind {
			continue
		}

		// @check if the authorizer is ignoring this namespace
		if utils.Contained(review.Request.Namespace, provider.FilterOn().IgnoreNamespaces) {
			log.WithFields(log.Fields{
				"name":      object.GetName(),
				"namespace": review.Request.Namespace,
				"provider":  provider.Name(),
			}).Warn("provider is ignored on this namespace")

			continue
		}
		object.SetNamespace(review.Request.Namespace)

		// @step: pass the object into the provider for authorization
		errs := func() field.ErrorList {
			now := time.Now()
			// @metric record the time taken per provider
			defer admissionAuthorizerLatencyMetric.WithLabelValues(provider.Name(), fmt.Sprintf("%d", i)).Observe(time.Since(now).Seconds())

			return provider.Admit(c.client, c.resourceCache, object)
		}()

		// @check if we found any error from the provider
		if len(errs) > 0 {
			admissionAuthorizerActionMetric.WithLabelValues(provider.Name(), actionDenied).Inc()

			// @check if it's an internal provider error and whether we should skip them
			skipme := false
			for _, x := range errs {
				if x.Type == field.ErrorTypeInternal {
					// @check if the provider is asking as to ignore internal failures
					if provider.FilterOn().IgnoreOnFailure {
						log.WithFields(log.Fields{
							"error":     x.Detail,
							"name":      object.GetGenerateName(),
							"namespace": object.GetNamespace(),
						}).Warn("internal provider error, skipping the provider result")

						skipme = true
					}
				}
			}
			if skipme {
				continue
			}

			var reasons []string
			for _, x := range errs {
				reasons = append(reasons, fmt.Sprintf("%s=%v : %s", x.Field, x.BadValue, x.Detail))
			}
			result.Allowed = false
			status.Message = strings.Join(reasons, ",")

			return result, nil
		}

		admissionAuthorizerActionMetric.WithLabelValues(provider.Name(), actionAccepted)
	}

	return result, nil
}

// getResourceForReview checks the kind of resource and decodes into the specific type
func (c *Admission) getResourceForReview(kind string, review *admission.AdmissionReview) (metav1.Object, error) {
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
		return nil, ErrNotSupported
	}

	// @step: decode the object into a object specification
	if err := json.Unmarshal(review.Request.Object.Raw, object); err != nil {
		return nil, err
	}

	return object, nil
}

// Start is repsonsible for starting the service up
func (c *Admission) Start() error {
	if c.client == nil {
		client, err := utils.GetKubernetesClient()
		if err != nil {
			return err
		}
		c.client = client
	}

	go func() {
		if err := c.engine.StartServer(c.server); err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Fatal("unable to create the http server")
		}
	}()

	return nil
}

// New creates and returns a new admission Admission
func New(config *Config, providers []api.Authorize) (*Admission, error) {
	if config.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	if err := config.IsValid(); err != nil {
		return nil, err
	}

	if len(providers) <= 0 {
		return nil, errors.New("no authorizers defined")
	}

	var evts []api.Sink

	// @step: create the event sinks
	if config.SlackWebHook != "" {
		e, err := slack.New(config.ClusterName, config.SlackWebHook)
		if err != nil {
			return nil, err
		}
		evts = append(evts, e)
	}

	if config.EnableEvents {
		e, err := kube.New()
		if err != nil {
			return nil, err
		}
		evts = append(evts, e)
	}

	eventmgr, err := events.New(config.RateLimit, evts...)
	if err != nil {
		return nil, err
	}

	log.Infof("policy admission controller, listen: %s", config.Listen)
	for _, x := range providers {
		log.Infof("enabling the authorizer: %s, ignored: %s, filter: %s", x.Name(),
			strings.Join(x.FilterOn().IgnoreNamespaces, ","), x.FilterOn().Kind)
	}

	c := &Admission{
		config:        config,
		events:        eventmgr,
		providers:     providers,
		resourceCache: cache.New(1*time.Minute, 5*time.Minute),
	}

	// @step: create the http router
	engine := echo.New()
	engine.Use(middleware.Recover())
	if c.config.EnableLogging {
		engine.Use(c.admissionMiddlerware())
	}
	engine.HideBanner = true
	engine.POST("/", c.admitHandler)
	engine.GET("/health", c.healthHandler)
	if config.EnableMetrics {
		engine.GET("/metrics", func(ctx echo.Context) error {
			prometheus.Handler().ServeHTTP(ctx.Response().Writer, ctx.Request())
			return nil
		})
	}

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
