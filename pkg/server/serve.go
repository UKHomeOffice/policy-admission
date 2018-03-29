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
	"net/http"
	"time"

	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
	admission "k8s.io/api/admission/v1beta1"
)

// admitHandler is responsible for handling the authorization request
func (c *Admission) admitHandler(ctx echo.Context) error {
	review := &admission.AdmissionReview{}

	// @step: we need to unmarshal the review
	if err := ctx.Bind(review); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("unable to decode the request")

		return ctx.NoContent(http.StatusBadRequest)
	}

	// @step: apply the policy against the review
	now := time.Now()
	if err := c.admit(review); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("unable to validation request against policy")

		return ctx.NoContent(http.StatusInternalServerError)
	}
	admissionRequestLatencyMetric.Observe(time.Since(now).Seconds())

	return ctx.JSON(http.StatusOK, review)
}

// healthHandler is just a health endpoint for the kubelet to call
func (c *Admission) healthHandler(ctx echo.Context) error {
	return ctx.String(http.StatusOK, "OK\n")
}
