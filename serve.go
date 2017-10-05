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

package main

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
	admission "k8s.io/api/admission/v1alpha1"
)

// admitHandler is responsible for handling the authorization request
func (c *controller) admitHandler(ctx echo.Context) error {
	review := &admission.AdmissionReview{}

	// @step: we need to unmarshal the review
	if err := ctx.Bind(review); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("unable to decode the request")

		return ctx.NoContent(http.StatusBadRequest)
	}

	// @step: apply the policy against the review
	if err := c.admit(review); err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("unable to apply the policy")

		return ctx.NoContent(http.StatusInternalServerError)
	}

	return ctx.JSON(http.StatusOK, review)
}

// healthHandler is just a health endpoint for the kubelet to call
func (c *controller) healthHandler(ctx echo.Context) error {
	return ctx.String(http.StatusOK, "OK\n")
}

// versionHandler is responsible for handling the version handler
func (c *controller) versionHandler(ctx echo.Context) error {
	return ctx.String(http.StatusOK, fmt.Sprintf("%s\n", Version))
}
