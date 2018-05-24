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
	"fmt"
	"io/ioutil"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	log "github.com/sirupsen/logrus"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// getKubernetesClient returns a kubernetes api client for us
func (c *Admission) getKubernetesClient() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	if c.config.EnableEvents && c.config.Namespace == "" {
		content, err := ioutil.ReadFile(serviceAccountNamespaceFile)
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

// createPodDeniedEvent is responsible for pushing a denial event into kubernetes events
func (c *Admission) createPodDeniedEvent(client kubernetes.Interface, object metav1.Object, reason string) {
	go func() {
		err := utils.Retry(5, time.Second*3, func() error {
			_, err := client.CoreV1().Events(c.config.Namespace).Create(&core.Event{
				Message: fmt.Sprintf("Pod denied in namespace: '%s', object: '%s'", object.GetNamespace(), object.GetGenerateName()),
				Reason:  "PodForbidden",
				Source:  core.EventSource{Component: admissionControllerName},
				Type:    "Warning",
			})

			return err
		})
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Warnf("failed to create the kubernetes event")
		}
	}()
}
