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

	"github.com/UKHomeOffice/policy-admission/pkg/api"

	"github.com/labstack/echo"
	"github.com/patrickmn/go-cache"
	"k8s.io/client-go/kubernetes"
)

const (
	// admissionControllerName is the name we register as
	admissionControllerName = "policy-admission.acp.homeoffice.gov.uk"
	// serviceAccountNamespaceFile is the path in a pod where we can find the namespace file
	serviceAccountNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// Admission is the admission controller service
type Admission struct {
	// providers is a collection of pod authorizers
	providers []api.Authorize
	// client the kubernetes client
	client kubernetes.Interface
	// config is the configuration for the service
	config *Config
	// engine is the http router
	engine *echo.Echo
	// server is the http server
	server *http.Server
	// cache is local cache for resources
	resourceCache *cache.Cache
}

// Config is the configuration for the service
type Config struct {
	// EnableEvents indicates we should enable event logging
	EnableEvents bool `yaml:"enable-events"`
	// EnableMetrics indicates we should expose the metrics
	EnableMetrics bool `yaml:"enable-metrics"`
	// EnableLogging indicates we want to see the admission request
	EnableLogging bool `yaml:"enable-logging"`
	// Listen is the interface we are listening on
	Listen string `yaml:"listen"`
	// Namespace is the kubernetes namespace we are running in
	Namespace string `yaml:"namespace"`
	// TLSKey is the path to a private key
	TLSKey string `yaml:"tls-key"`
	// TLSCert is the path to a certificate
	TLSCert string `yaml:"tls-cert"`
	// Verbose indicates verbose logging
	Verbose bool `yaml:"verbose"`
}
