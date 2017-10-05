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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
	admission "k8s.io/api/admission/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	core "k8s.io/kubernetes/pkg/api"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
}

type controller struct {
	sync.RWMutex

	policy *podAuthorizer
	client kubernetes.Interface
	config *Config
	server *http.Server
}

// newAdmissionController creates, registers and starts the admission controller
func newAdmissionController(config *Config) (*controller, error) {
	if err := config.isValid(); err != nil {
		return nil, err
	}
	log.Infof("starting the policy admission controller, version: %s, listen: %s", Version, config.Listen)

	// @step: create a authorizer
	policies, err := createPodAuthorizorConfig(config.Policies)
	if err != nil {
		return nil, err
	}

	authorizer, err := newPodAuthorizer(policies)
	if err != nil {
		return nil, err
	}

	c := &controller{config: config, policy: authorizer}

	// @step: create the http router
	engine := echo.New()
	engine.HideBanner = true
	engine.Use(middleware.Recover())
	engine.GET("/health", c.healthHandler)
	engine.GET("/version", c.versionHandler)

	c.server = &http.Server{
		Addr:         c.config.Listen,
		Handler:      engine,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  5 * time.Second,
	}

	// @step: load the tls settings if any
	if config.TLSCert != "" && config.TLSKey != "" {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.NoClientCert}

		cert, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		c.server.TLSConfig = tlsConfig
	}

	// @step: are we watching for file changes
	if c.config.WatchConfig {
		if err := c.createPolicyChangesWatcher(c.config.Policies); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// admit is responsible for applying the policy on the incoming request
func (c *controller) admit(review *admission.AdmissionReview) error {
	ok, message := func() (bool, string) {
		kind := review.Spec.Kind.Kind
		if kind != "Pod" {
			return false, fmt.Sprintf("invalid object for review: %s, expected: Pod", kind)
		}

		// @step: decode the object into a pod specification
		object := &core.Pod{}
		if err := json.Unmarshal(review.Spec.Object.Raw, object); err != nil {
			return false, fmt.Sprintf("unable to decode object spec: %s", err)
		}

		// @check if the namespace has a security policy annotation
		namespace, err := c.client.CoreV1().Namespaces().Get(review.Spec.Namespace, metav1.GetOptions{})
		if err != nil {
			log.WithFields(log.Fields{
				"error":     err.Error(),
				"namespace": review.Spec.Namespace,
			}).Error("unable to retrieve namespace")

			return false, "unable to get namespace"
		}
		// @check if a policy is selected, ensure the policy exixts
		selected := namespace.GetAnnotations()[SecurityPolicyAnnotation]

		// @check the pod spec against the policy - this operating has to be serialized
		c.RLock()
		defer c.RUnlock()

		violations := c.policy.authorize(selected, object)
		if len(violations) > 0 {
			return false, "security violation"
		}

		return true, ""
	}()
	if !ok {
		log.WithFields(log.Fields{
			"error":     message,
			"name":      review.Spec.Name,
			"namespace": review.Spec.Namespace,
		}).Warn(message)

		review.Status.Allowed = false
		review.Status.Result = &metav1.Status{
			Code:    http.StatusForbidden,
			Message: message,
			Reason:  metav1.StatusReasonForbidden,
			Status:  metav1.StatusFailure,
		}

		return nil
	}

	review.Status.Allowed = true

	return nil
}

// createPolicyChangesWatcher is responsible for updating the secuity policy on file changes
// @TODO perhaps move the configuraton to viper?
func (c *controller) createPolicyChangesWatcher(filename string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	if err := watcher.Add(path.Dir(filename)); err != nil {
		return err
	}

	go func() {
		for e := range watcher.Events {
			if e.Op&fsnotify.Write == fsnotify.Write || e.Op&fsnotify.Create == fsnotify.Create {
				// @check if the file change if our configutation file?
				if e.Name == filename {
					authorizer, err := func() (*podAuthorizer, error) {
						config, err := createPodAuthorizorConfig(filename)
						if err != nil {
							return nil, err
						}

						return newPodAuthorizer(config)
					}()
					if err != nil {
						log.WithFields(log.Fields{
							"error": err.Error(),
						}).Error("unable reload policy on content change")
						continue
					}

					c.updatePolicyAuthorizer(authorizer)
				}
			}
		}
	}()

	return nil
}

// updatePolicyAuthorizer is responsible for updating the current authorizer
func (c *controller) updatePolicyAuthorizer(authorizer *podAuthorizer) {
	log.Info("updating the authorizer with new policy")

	c.Lock()
	defer c.Unlock()

	c.policy = authorizer
}

// startController is repsonsible for starting the service up
func (c *controller) startController() error {
	// @step: attempt to create a kubernetes client
	client, err := getKubernetesClient()
	if err != nil {
		return err
	}
	c.client = client

	go func() {
		if err := c.server.ListenAndServe(); err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Fatal("unable to create the http service")
		}
	}()

	return nil
}

// createPodAuthorizorConfig is responisble for reading the policies file
func createPodAuthorizorConfig(filename string) (*podAuthorizerConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	content, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	config := &podAuthorizerConfig{}
	if err := yaml.Unmarshal(content, config); err != nil {
		return nil, err
	}

	return config, nil
}

// getKubernetesClient returns a kubernetes api client for us
func getKubernetesClient() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(config)
}
