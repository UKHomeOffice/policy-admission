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
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/ghodss/yaml"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	log "github.com/sirupsen/logrus"
	admission "k8s.io/api/admission/v1alpha1"
	api "k8s.io/api/core/v1"
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
	engine *echo.Echo
	server *http.Server
}

// newAdmissionController creates and returns a new admission controller
// - this indirection is really nothing more but to make testing eaiser i.e no need to write config files
func newAdmissionController(config *Config) (*controller, error) {
	if err := config.isValid(); err != nil {
		return nil, err
	}

	policies, err := createPodAuthorizorConfig(config.Policies)
	if err != nil {
		return nil, err
	}

	return newAdmissionControllerWithConfig(config, policies)
}

// newAdmissionControllerWithConfig creates, registers and starts the admission controller
func newAdmissionControllerWithConfig(config *Config, policies *podAuthorizerConfig) (*controller, error) {
	if err := config.isValid(); err != nil {
		return nil, err
	}
	log.Infof("starting the policy admission controller, version: %s, listen: %s", Version, config.Listen)

	if config.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	authorizer, err := newPodAuthorizer(policies)
	if err != nil {
		return nil, err
	}

	c := &controller{config: config, policy: authorizer}

	// @step: create the http router
	c.engine = echo.New()
	c.engine.HideBanner = true
	c.engine.Use(middleware.Recover())
	c.engine.POST("/", c.admitHandler)
	c.engine.GET("/health", c.healthHandler)
	c.engine.GET("/version", c.versionHandler)

	c.server = &http.Server{
		Addr:         c.config.Listen,
		Handler:      c.engine,
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
	if c.config.EnableReload {
		if err := c.createPolicyChangesWatcher(c.config.Policies); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// admit is responsible for applying the policy on the incoming request
func (c *controller) admit(review *admission.AdmissionReview) error {
	object := &core.Pod{}

	ok, message := func() (bool, string) {
		// the policy to check the pod against
		var selected string

		kind := review.Spec.Kind.Kind
		if kind != "Pod" {
			return false, fmt.Sprintf("invalid object for review: %s, expected: pod", kind)
		}

		// @step: decode the object into a pod specification
		if err := json.Unmarshal(review.Spec.Object.Raw, object); err != nil {
			return false, fmt.Sprintf("unable to decode object spec: %s", err)
		}
		object.Namespace = review.Spec.Namespace

		log.WithFields(log.Fields{
			"namespace": object.Namespace,
			"pod":       object.Name,
			"spec":      fmt.Sprintf("%s", review.Spec.Object.Raw),
		}).Debug("pod spec up for review")

		// @check if the namespace has a security policy annotation
		namespace, err := c.client.CoreV1().Namespaces().Get(review.Spec.Namespace, metav1.GetOptions{})
		if err != nil {
			log.WithFields(log.Fields{
				"error":     err.Error(),
				"namespace": review.Spec.Namespace,
			}).Warnf("unable to retrieve namespace, selecting default policy")
		}
		if namespace != nil {
			// @check if a policy is selected, ensure the policy exixts
			selected = namespace.GetAnnotations()[SecurityPolicyAnnotation]
		}

		// @check the pod spec against the policy - this operating has to be serialized
		c.RLock()
		defer c.RUnlock()

		admit, violations := c.policy.authorize(selected, object)
		if !admit {
			var reasons []string
			for _, x := range violations {
				reasons = append(reasons, fmt.Sprintf("%s", x.Detail))
			}

			return false, strings.Join(reasons, ",")
		}

		return true, ""
	}()
	if !ok {
		log.WithFields(log.Fields{
			"error":     message,
			"namespace": review.Spec.Namespace,
			"pod":       object.GenerateName,
		}).Warn("authorization for pod execution denied")

		review.Status.Allowed = false
		review.Status.Result = &metav1.Status{
			Code:    http.StatusForbidden,
			Message: message,
			Reason:  metav1.StatusReasonForbidden,
			Status:  metav1.StatusFailure,
		}

		if c.config.EnableEvents {
			_, err := c.client.CoreV1().Events(c.config.Namespace).Create(&api.Event{
				Reason:  "PodForbidden",
				Message: fmt.Sprintf("Pod denied in namespace: '%s', pod: '%s'", review.Spec.Namespace, object.GenerateName),
				Source:  api.EventSource{Component: AdmissionControllerName},
				Type:    "Warning",
			})
			if err != nil {
				log.WithFields(log.Fields{
					"error": err.Error(),
				}).Warnf("failed to create the kubernetes event")
			}
		}

		return nil
	}
	review.Status.Allowed = true

	log.WithFields(log.Fields{
		"namespace": review.Spec.Namespace,
		"pod":       object.GenerateName,
	}).Info("pod is authorized for execution")

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
	client, err := c.getKubernetesClient()
	if err != nil {
		return err
	}
	c.client = client

	go func() {
		if err := c.engine.StartServer(c.server); err != nil {
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
func (c *controller) getKubernetesClient() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	if c.config.EnableEvents && c.config.Namespace == "" {
		content, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Errorf("unable to read namesapce from serviceaccount file, disabling events")

			c.config.EnableEvents = false
		}
		c.config.Namespace = string(content)
	}

	return kubernetes.NewForConfig(config)
}
