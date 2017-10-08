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
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admission "k8s.io/api/admission/v1alpha1"
	authentication "k8s.io/api/authentication/v1"
	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	core "k8s.io/kubernetes/pkg/api"
)

func TestVersionHandler(t *testing.T) {
	requests := []request{
		{
			URI:             "/version",
			ExpectedCode:    http.StatusOK,
			ExpectedContent: Version + "\n",
		},
	}
	newFakeController().runTests(t, requests)
}

func TestHealthHandler(t *testing.T) {
	requests := []request{
		{URI: "/health", ExpectedCode: http.StatusOK},
	}
	newFakeController().runTests(t, requests)
}

func TestAdmitHandlerBad(t *testing.T) {
	requests := []request{
		{URI: "/", Method: http.MethodPost, Body: "bad", ExpectedCode: http.StatusBadRequest},
	}
	newFakeController().runTests(t, requests)
}

func TestAdmitHandler(t *testing.T) {
	priv := false
	privilegedOn := true
	requests := []request{
		{
			// ensure a default pod can get through
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "test"},
				Spec: core.PodSpec{
					Containers: []core.Container{
						{Name: "test", Image: "nginx", SecurityContext: &core.SecurityContext{Privileged: &priv}},
					},
					SecurityContext: &core.PodSecurityContext{},
				},
			},
			ExpectedStatus: &admission.AdmissionReviewStatus{Allowed: true},
		},
		{
			// ensure a host network is denied
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "test"},
				Spec:       core.PodSpec{SecurityContext: &core.PodSecurityContext{HostNetwork: true}},
			},
			ExpectedStatus: &admission.AdmissionReviewStatus{
				Result: &metav1.Status{
					Code:    http.StatusForbidden,
					Message: "Host network is not allowed to be used",
					Reason:  metav1.StatusReasonForbidden,
					Status:  metav1.StatusFailure,
				},
			},
		},
		{
			// ensure a host network is allow for kube-system
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "kube-system"},
				Spec:       core.PodSpec{SecurityContext: &core.PodSecurityContext{HostNetwork: true}},
			},
			ExpectedStatus: &admission.AdmissionReviewStatus{Allowed: true},
		},
		{
			// ensure a when namespace not there, default to default policy
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "not-there"},
				Spec:       core.PodSpec{SecurityContext: &core.PodSecurityContext{HostNetwork: true}},
			},
			ExpectedStatus: &admission.AdmissionReviewStatus{
				Result: &metav1.Status{
					Code:    http.StatusForbidden,
					Message: "Host network is not allowed to be used",
					Reason:  metav1.StatusReasonForbidden,
					Status:  metav1.StatusFailure,
				},
			},
		},
		{
			// ensure a host volume is deny
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "not-there"},
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{},
					Volumes: []core.Volume{
						{
							Name:         "deny_me",
							VolumeSource: core.VolumeSource{HostPath: &core.HostPathVolumeSource{Path: "/"}},
						},
					},
				},
			},
			ExpectedStatus: &admission.AdmissionReviewStatus{
				Result: &metav1.Status{
					Code:    http.StatusForbidden,
					Message: "hostPath volumes are not allowed to be used",
					Reason:  metav1.StatusReasonForbidden,
					Status:  metav1.StatusFailure,
				},
			},
		},
		{
			// ensure a container cannot run with privs
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "test"},
				Spec: core.PodSpec{
					Containers: []core.Container{
						{Name: "test", Image: "nginx", SecurityContext: &core.SecurityContext{Privileged: &privilegedOn}},
					},
					SecurityContext: &core.PodSecurityContext{},
				},
			},
			ExpectedStatus: &admission.AdmissionReviewStatus{
				Result: &metav1.Status{
					Code:    http.StatusForbidden,
					Message: "Privileged containers are not allowed",
					Reason:  metav1.StatusReasonForbidden,
					Status:  metav1.StatusFailure,
				},
			},
		},
		{
			// ensure a container can run in kube-system
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "kube-system"},
				Spec: core.PodSpec{
					Containers: []core.Container{
						{Name: "test", Image: "nginx", SecurityContext: &core.SecurityContext{Privileged: &privilegedOn}},
					},
					SecurityContext: &core.PodSecurityContext{},
				},
			},
			ExpectedStatus: &admission.AdmissionReviewStatus{Allowed: true},
		},
	}
	newFakeController().runTests(t, requests)
}

func TestAdmitHandlerNamespaceIgnored(t *testing.T) {
	requests := []request{
		{
			// ensure a when namespace is ignored it allowed through
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ignored"},
				Spec:       core.PodSpec{SecurityContext: &core.PodSecurityContext{HostNetwork: true}},
			},
			ExpectedStatus: &admission.AdmissionReviewStatus{Allowed: true},
		},
	}
	newFakeController().runTests(t, requests)
}

func TestAdmitHandlerWithOutNamespaceAnnotation(t *testing.T) {
	c := newFakeController()
	c.service.client.CoreV1().Namespaces().Create(&api.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	})

	requests := []request{
		{
			// ensure a when namespace not there, default to default policy
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"},
				Spec:       core.PodSpec{SecurityContext: &core.PodSecurityContext{HostNetwork: true}},
			},
			ExpectedStatus: &admission.AdmissionReviewStatus{
				Result: &metav1.Status{
					Code:    http.StatusForbidden,
					Message: "Host network is not allowed to be used",
					Reason:  metav1.StatusReasonForbidden,
					Status:  metav1.StatusFailure,
				},
			},
		},
	}
	c.runTests(t, requests)
}

func TestAdmitHandlerWithNamespaceAnnotation(t *testing.T) {
	c := newFakeController()
	c.service.client.CoreV1().Namespaces().Create(&api.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "default",
			Annotations: map[string]string{SecurityPolicyAnnotation: "privileged"},
		},
	})

	requests := []request{
		{
			// ensure a when namespace not there, default to default policy
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"},
				Spec:       core.PodSpec{SecurityContext: &core.PodSecurityContext{HostNetwork: true}},
			},
			ExpectedStatus: &admission.AdmissionReviewStatus{Allowed: true},
		},
	}
	c.runTests(t, requests)
}

type request struct {
	Method string
	Pod    *core.Pod
	Review *admission.AdmissionReview
	Body   string
	URI    string

	ExpectedCode    int
	ExpectedContent string
	ExpectedStatus  *admission.AdmissionReviewStatus
}

type fakeController struct {
	server  *httptest.Server
	service *controller
}

// runTests performs a series of tests on the service
func (c *fakeController) runTests(t *testing.T, requests []request) {
	for i, x := range requests {
		if x.Method == "" {
			x.Method = http.MethodGet
		}

		if x.Pod != nil {
			content, err := json.Marshal(x.Pod)
			if err != nil {
				t.Errorf("case %d, unable encode pod, error: %s", i, err)
				continue
			}

			x.Method = http.MethodPost
			x.URI = "/"
			x.Review = &admission.AdmissionReview{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "admission.k8s.io/v1alpha1",
					Kind:       "AdmissionReview",
				},
				Spec: admission.AdmissionReviewSpec{
					Kind:      metav1.GroupVersionKind{Group: "core", Version: "v1", Kind: "Pod"},
					Name:      x.Pod.Name,
					Namespace: x.Pod.Namespace,
					Object:    runtime.RawExtension{Raw: content},
					Operation: admission.Create,
					Resource:  metav1.GroupVersionResource{Group: "core", Version: "v1", Resource: "pods"},
					UserInfo:  authentication.UserInfo{Username: "admin"},
				},
			}
		}

		body := bytes.NewBuffer([]byte{})
		if x.Review != nil {
			encoded, err := json.Marshal(x.Review)
			require.NoError(t, err)
			require.NotEmpty(t, encoded)
			body.Write(encoded)
		}

		if len(x.Body) > 0 {
			body.Write([]byte(x.Body))
		}

		req, err := http.NewRequest(x.Method, c.server.URL+x.URI, body)
		require.NoError(t, err, "case %d should not have thrown error: %s", i, err)
		require.NotNil(t, req, "case %d response should not be nil", i)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err, "case %d should not have thrown error: %s", i, err)
		require.NotNil(t, resp, "case %d response should not be nil", i)
		content, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err, "case %d unable to read content, error: %s", i, err)

		if x.ExpectedCode != 0 {
			assert.Equal(t, x.ExpectedCode, resp.StatusCode, "case %d, expected: %d, got: %d", i, x.ExpectedCode, resp.StatusCode)
		}
		if x.ExpectedContent != "" {
			assert.Equal(t, x.ExpectedContent, string(content), "case %d, expected: %s, got: %s", i, x.ExpectedContent, string(content))
		}
		if x.ExpectedStatus != nil {
			status := &admission.AdmissionReview{}
			if err := json.Unmarshal(content, status); err != nil {
				t.Errorf("case %d, unable to decode responce, error: %s", i, err)
				continue
			}
			assert.Equal(t, *x.ExpectedStatus, status.Status)
		}
	}
}
