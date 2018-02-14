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
	"net/http/httputil"
	"time"

	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
)

// admissionMiddlerware is middleware to log the admission requests
func (c *Admission) admissionMiddlerware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			request := ctx.Request()
			admission, err := httputil.DumpRequest(request, true)
			if err != nil {
				log.WithFields(log.Fields{"error": err.Error()}).Error("unable to read the request body")
			}
			start := time.Now()
			if err = next(ctx); err != nil {
				ctx.Error(err)
			}
			stop := time.Now()

			log.WithFields(log.Fields{
				"code":    ctx.Response().Status,
				"host":    request.Host,
				"method":  request.Method,
				"request": admission,
				"time":    stop.Sub(start).String(),
				"uri":     request.RequestURI,
			}).Info("http request")

			return nil
		}
	}
}
