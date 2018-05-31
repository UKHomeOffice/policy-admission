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

package kube

import (
	"fmt"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

type kubeSink struct {
	// client is the kubernete client
	client kubernetes.Interface
}

// New returns a kubernetes
func New() (api.Sink, error) {
	client, err := utils.GetKubernetesClient()
	if err != nil {
		return nil, err
	}

	return &kubeSink{client: client}, nil
}

// Send is responsible for sending the event into the kubernete events
func (k *kubeSink) Send(event *api.Event) error {
	_, err := k.client.CoreV1().Events(event.Object.GetNamespace()).Create(&core.Event{
		Message: fmt.Sprintf("Denied in namespace: '%s', event.Object: '%s', reason: %s", event.Object.GetNamespace(), event.Object.GetGenerateName(), event.Detail),
		Reason:  "Forbidden",
		Source:  core.EventSource{Component: api.AdmissionControllerName},
		Type:    "Warning",
	})

	return err
}
