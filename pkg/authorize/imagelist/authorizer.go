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

package imagelist

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"github.com/patrickmn/go-cache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
	core "k8s.io/kubernetes/pkg/api"
)

// authorizer is used to wrap the interaction with the psp runtime
type authorizer struct {
	// the configuration for the enforcer
	config *Config
	// the endpoint to call
	endpoint *url.URL
	// the http client used to speak to the endpoint
	hc *http.Client
	// a local cache for results
	lcache *cache.Cache
}

// Admit is responsible for adding a policy to the enforcers
func (c *authorizer) Admit(client kubernetes.Interface, mcache *cache.Cache, object metav1.Object) field.ErrorList {
	var errs field.ErrorList

	pod, ok := object.(*core.Pod)
	if !ok {
		return append(errs, field.InternalError(field.NewPath("object"), errors.New("invalid object, expected Pod")))
	}

	// @check the init containers are valid
	errs = append(errs, c.validateImage(field.NewPath("spec.initContainers"), pod.Spec.InitContainers)...)
	// @check the pod containers are valid
	errs = append(errs, c.validateImage(field.NewPath("spec.containers"), pod.Spec.Containers)...)

	return errs
}

// validateImage is responsible for calling upstream to the provider
func (c *authorizer) validateImage(fld *field.Path, container []core.Container) field.ErrorList {
	var errs field.ErrorList
	var err error
	// @step: iterate the container and check the are cool
	for i, container := range container {
		// @check if the result was cached and if not, we need to make the call
		permit, found := c.lcache.Get(container.Image)
		if !found {
			start := time.Now()
			permit, err = c.handleImageRequest(container.Image)
			if err != nil {
				return append(errs, field.InternalError(field.NewPath("imagelist"), fmt.Errorf("communication failure with imagelist: %s", err.Error())))
			}
			imageListRequestLatencyMetric.Observe(time.Since(start).Seconds())
		}
		allowed := permit.(bool)

		// @step: how long should we cache the result
		expiration := c.config.CacheSuccess
		if !allowed {
			expiration = c.config.CacheFailure
		}

		// @step: update the cache with the result
		c.lcache.Add(container.Image, allowed, expiration)

		if !allowed {
			errs = append(errs, field.Invalid(fld.Index(i).Child("image"), container.Image,
				fmt.Sprintf("%s: denied by imagelist policy", container.Image)))
		}
	}

	return errs
}

// handleImageRequest is resposible for making the request to the upstream service
func (c *authorizer) handleImageRequest(image string) (bool, error) {
	uri := fmt.Sprintf("%s/%s", c.endpoint.String(), image)

	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return false, err
	}
	if c.config.Token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer: %s", c.config.Token))
	}

	ctx, cancel := context.WithCancel(context.TODO())
	time.AfterFunc(c.config.Timeout, func() {
		cancel()
	})

	resp, err := c.hc.Do(req.WithContext(ctx))
	if err != nil {
		return false, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("invalid status return: %d", resp.StatusCode)
	}
}

// FilterOn returns the authorizer handle
func (c *authorizer) FilterOn() api.Filter {
	return api.Filter{
		IgnoreNamespaces: c.config.IgnoreNamespaces,
		Kind:             api.FilterPods,
	}
}

// Name returns the name of the provider
func (c *authorizer) Name() string {
	return Name
}

// New creates and returns a pod authorization implementation
func New(config *Config) (api.Authorize, error) {
	if config == nil {
		config = NewDefaultConfig()
	}

	endpoint, err := url.Parse(config.EndpointURL)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %s", err)
	}

	// @step: create the http client
	tlsOptions := &tls.Config{
		InsecureSkipVerify: config.SkipTLSVerify,
		MinVersion:         tls.VersionTLS12,
	}
	if config.ClientCertificateCert != "" && config.ClientCertificateKey != "" {
		cert, err := tls.LoadX509KeyPair(config.ClientCertificateCert, config.ClientCertificateKey)
		if err != nil {
			return nil, fmt.Errorf("unable to load client certificate: %s", err)
		}
		tlsOptions.Certificates = []tls.Certificate{cert}
	}
	if config.ClientCA != "" {
		ca, err := ioutil.ReadFile(config.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("unable to local ca: %s", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(ca)
		tlsOptions.RootCAs = pool
	}

	hc := &http.Client{
		Transport: &http.Transport{
			ExpectContinueTimeout: time.Duration(10 * time.Second),
			IdleConnTimeout:       time.Duration(10 * time.Second),
			ResponseHeaderTimeout: time.Duration(10 * time.Second),
			TLSClientConfig:       tlsOptions,
		},
	}
	lcache := cache.New(time.Duration(5*time.Minute), time.Duration(5*time.Minute))

	return &authorizer{
		config:   config,
		endpoint: endpoint,
		hc:       hc,
		lcache:   lcache,
	}, nil
}

// NewFromFile reads the configuration path and returns the authorizer
func NewFromFile(path string) (api.Authorize, error) {
	if path == "" {
		return New(nil)
	}
	cfg := &Config{}
	if err := utils.NewConfig(path).Read(cfg); err != nil {
		return nil, err
	}

	return New(cfg)
}
