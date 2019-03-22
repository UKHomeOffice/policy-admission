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
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	log "github.com/sirupsen/logrus"
	admission "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	// The request has been accepted
	actionAccepted = "accept"
	// The request has been refused
	actionDenied = "deny"
	// The request has cause an error
	actionErrored = "error"
)

// authorize is responsible for applying the policy on the incoming request
func (c *Admission) authorize(ctx context.Context, review *admission.AdmissionReview) error {
	// @check if the review is for something we can process
	object, err := decodeObject(review.Request.Kind.Kind, review)
	if err != nil {
		log.WithFields(log.Fields{
			"error":     err.Error(),
			"id":        utils.GetTRX(ctx),
			"name":      review.Request.Name,
			"namespace": review.Request.Namespace,
		}).Errorf("unable to decode object for review")

		return err
	}

	// @step: attempt to get the object authorized
	denied, reason, err := c.authorizeResource(ctx, object, review.Request.Kind)
	if err != nil {
		log.WithFields(log.Fields{
			"error":     err.Error(),
			"id":        utils.GetTRX(ctx),
			"name":      review.Request.Name,
			"namespace": review.Request.Namespace,
		}).Errorf("unable to handle admission review")

		return err
	}

	// @check if the object was rejected
	if denied {
		admissionTotalMetric.WithLabelValues(actionDenied).Inc()

		log.WithFields(log.Fields{
			"error":     reason,
			"group":     review.Request.Kind.Group,
			"id":        utils.GetTRX(ctx),
			"kind":      review.Request.Kind.Kind,
			"name":      review.Request.Name,
			"namespace": review.Request.Namespace,
			"uid":       review.Request.UserInfo.UID,
			"user":      review.Request.UserInfo.Username,
			"version":   review.Request.Kind.Version,
		}).Warn("authorization for object execution denied")

		review.Response = &admission.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Code:    http.StatusForbidden,
				Message: reason,
				Reason:  metav1.StatusReasonForbidden,
				Status:  metav1.StatusFailure,
			},
		}

		// @step: log the denial is required
		go c.events.Send(&api.Event{
			Detail: reason,
			Object: object,
			Review: review.Request,
		})

		return nil
	}

	admissionTotalMetric.WithLabelValues(actionAccepted).Inc()

	review.Response = &admission.AdmissionResponse{Allowed: true}

	log.WithFields(log.Fields{
		"group":     review.Request.Kind.Group,
		"id":        utils.GetTRX(ctx),
		"kind":      review.Request.Kind.Kind,
		"name":      review.Request.Name,
		"namespace": review.Request.Namespace,
		"uid":       review.Request.UserInfo.UID,
		"user":      review.Request.UserInfo.Username,
		"version":   review.Request.Kind.Version,
	}).Info("object has been authorized for execution")

	return nil
}

// authorizeResource is responsible for handling the review and returning a result
func (c *Admission) authorizeResource(ctx context.Context, object metav1.Object, kind metav1.GroupVersionKind) (bool, string, error) {
	// @step: create a authorization context
	cx := &api.Context{
		Cache:  c.resourceCache,
		Client: c.client,
		Group:  kind,
		Object: object,
		Prefix: c.config.ControllerName,
	}

	// @step: iterate the authorizers and fail on first refusal
	for i, provider := range c.providers {
		// @check if this authorizer is listening to this type
		if !provider.FilterOn().Matched(kind, object.GetNamespace()) {
			log.WithFields(log.Fields{
				"group":     kind.Group,
				"id":        utils.GetTRX(ctx),
				"kind":      kind.Kind,
				"namespace": object.GetNamespace(),
				"provider":  provider.Name(),
			}).Debug("provider is not filtering on this object")

			continue
		}

		// @step: pass the object into the provider for authorization
		errs := func() field.ErrorList {
			now := time.Now()
			// @metric record the time taken per provider
			defer admissionAuthorizerLatencyMetric.WithLabelValues(provider.Name(), fmt.Sprintf("%d", i)).Observe(time.Since(now).Seconds())

			return provider.Admit(ctx, cx)
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
							"group":     kind.Group,
							"id":        utils.GetTRX(ctx),
							"kind":      kind.Kind,
							"name":      object.GetGenerateName(),
							"namespace": object.GetNamespace(),
						}).Error("internal provider error, skipping the provider result")

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

			return true, strings.Join(reasons, ","), nil
		}

		admissionAuthorizerActionMetric.WithLabelValues(provider.Name(), actionAccepted)
	}

	return false, "", nil
}
