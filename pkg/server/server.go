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
	"errors"
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
	engine.Use(middleware.RequestID())
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
