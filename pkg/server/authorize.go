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
	kind := review.Request.Kind.Kind
	object, err := c.getResourceForReview(kind, review)
	if err != nil {
		if err != ErrNotSupported {
			log.WithFields(log.Fields{
				"error":     err.Error(),
				"name":      review.Request.Name,
				"namespace": review.Request.Namespace,
				"trx-id":    utils.GetTRX(ctx),
			}).Errorf("unable to decode object for review review")

			return err
		}

		// @else the object was not supported, we permit through but raise a warning
		log.WithFields(log.Fields{
			"group":     review.Request.Kind.Group,
			"kind":      review.Request.Kind.Kind,
			"name":      review.Request.Name,
			"namespace": review.Request.Namespace,
			"trx-id":    utils.GetTRX(ctx),
		}).Warn("object kind is not suppported")
	}

	if object != nil {
		denied, reason, err := c.handleAuthorization(ctx, object, kind)
		if err != nil {
			log.WithFields(log.Fields{
				"error":     err.Error(),
				"name":      review.Request.Name,
				"namespace": review.Request.Namespace,
				"trx-id":    utils.GetTRX(ctx),
			}).Errorf("unable to handle admission review")

			return err
		}

		// @check if the object was rejected
		if denied {
			admissionTotalMetric.WithLabelValues(actionDenied).Inc()

			log.WithFields(log.Fields{
				"error":     reason,
				"group":     review.Request.Kind.Group,
				"kind":      review.Request.Kind.Kind,
				"name":      review.Request.Name,
				"namespace": review.Request.Namespace,
				"user-uid":  review.Request.UserInfo.UID,
				"user":      review.Request.UserInfo.Username,
				"trx-id":    utils.GetTRX(ctx),
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
		"trx-id":    utils.GetTRX(ctx),
	}).Info("object has been authorized for execution")

	return nil
}

// handleAuthorization is responsible for handling the review and returning a result
func (c *Admission) handleAuthorization(ctx context.Context, object metav1.Object, kind string) (bool, string, error) {
	cx := &api.Context{
		Cache:  c.resourceCache,
		Client: c.client,
		Object: object,
		Prefix: c.config.ControllerName,
	}

	// @step: iterate the authorizers and fail on first refusal
	for i, provider := range c.providers {

		// @check if this authorizer is listening to this type
		if provider.FilterOn().Kind != api.FilterAll && provider.FilterOn().Kind != kind {
			continue
		}

		// @check if the authorizer is ignoring this namespace
		if utils.Contained(object.GetNamespace(), provider.FilterOn().IgnoreNamespaces) {
			log.WithFields(log.Fields{
				"name":      object.GetName(),
				"namespace": object.GetNamespace(),
				"provider":  provider.Name(),
				"trx-id":    utils.GetTRX(ctx),
			}).Warn("provider is ignored on this namespace")

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
							"name":      object.GetGenerateName(),
							"namespace": object.GetNamespace(),
							"trx-id":    utils.GetTRX(ctx),
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

			return true, strings.Join(reasons, ","), nil
		}

		admissionAuthorizerActionMetric.WithLabelValues(provider.Name(), actionAccepted)
	}

	return false, "", nil
}
