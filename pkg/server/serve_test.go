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
	"testing"

	admission "k8s.io/api/admission/v1beta1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	isTrue  = true
	isFalse = false
)

func TestHealthHandler(t *testing.T) {
	requests := []request{
		{URI: "/health", ExpectedCode: http.StatusOK},
	}
	newTestAdmissionWithImagesContext().runTests(t, requests)
}

func TestAdmitHandlerBad(t *testing.T) {
	requests := []request{
		{URI: "/", Method: http.MethodPost, Body: "bad", ExpectedCode: http.StatusBadRequest},
	}
	newTestAdmissionWithImagesContext().runTests(t, requests)
}

func TestAdmitHandlerChecks(t *testing.T) {
	requests := []request{
		{
			// ensure an images inside the registry is permitted
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "test"},
				Spec: core.PodSpec{
					Containers: []core.Container{
						{Name: "test", Image: "docker.io/nginx:latest"},
					},
				},
			},
			ExpectedStatus: &admission.AdmissionResponse{Allowed: true},
		},
		{
			// ensure a pod outside of the regustry is denied
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "test"},
				Spec: core.PodSpec{
					Containers: []core.Container{
						{Name: "test", Image: "nginx:latest"},
					},
				},
			},
			ExpectedStatus: &admission.AdmissionResponse{
				Result: &metav1.Status{
					Code:    http.StatusForbidden,
					Message: "spec.containers[0].image=nginx:latest : image: nginx:latest denied by policy",
					Reason:  metav1.StatusReasonForbidden,
					Status:  metav1.StatusFailure,
				},
			},
		},
	}
	newTestAdmissionWithImagesContext().runTests(t, requests)
}
