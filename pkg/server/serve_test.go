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

	"github.com/UKHomeOffice/policy-admission/pkg/authorize/securitycontext"

	admission "k8s.io/api/admission/v1alpha1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	core "k8s.io/kubernetes/pkg/api"
)

var (
	isTrue  = true
	isFalse = false
)

func TestHealthHandler(t *testing.T) {
	requests := []request{
		{URI: "/health", ExpectedCode: http.StatusOK},
	}
	newTestAdmissionWithSecurityContext().runTests(t, requests)
}

func TestAdmitHandlerBad(t *testing.T) {
	requests := []request{
		{URI: "/", Method: http.MethodPost, Body: "bad", ExpectedCode: http.StatusBadRequest},
	}
	newTestAdmissionWithSecurityContext().runTests(t, requests)
}

func TestAdmitHandlerChecks(t *testing.T) {
	requests := []request{
		{
			// ensure a default pod can get through
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "test"},
				Spec: core.PodSpec{
					Containers: []core.Container{
						{Name: "test", Image: "nginx", SecurityContext: &core.SecurityContext{Privileged: &isFalse, RunAsNonRoot: &isTrue}},
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
					Message: "spec.securityContext.hostNetwork=true : Host network is not allowed to be used",
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
					Message: `not-there=<nil> : namespaces "not-there" not found`,
					Reason:  metav1.StatusReasonForbidden,
					Status:  metav1.StatusFailure,
				},
			},
		},
		{
			// ensure a host volume is deny
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "test"},
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
					Message: "spec.volumes[0]=hostPath : hostPath volumes are not allowed to be used",
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
						{Name: "test", Image: "nginx", SecurityContext: &core.SecurityContext{Privileged: &isTrue, RunAsNonRoot: &isTrue}},
					},
					SecurityContext: &core.PodSecurityContext{},
				},
			},
			ExpectedStatus: &admission.AdmissionReviewStatus{
				Result: &metav1.Status{
					Code:    http.StatusForbidden,
					Message: "spec.containers[0].securityContext.privileged=true : Privileged containers are not allowed",
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
						{Name: "test", Image: "nginx", SecurityContext: &core.SecurityContext{Privileged: &isTrue, RunAsNonRoot: &isTrue}},
					},
					SecurityContext: &core.PodSecurityContext{},
				},
			},
			ExpectedStatus: &admission.AdmissionReviewStatus{Allowed: true},
		},
		{
			// ensure a container cannot run without run-as-nonroot
			Pod: &core.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "test"},
				Spec: core.PodSpec{
					Containers: []core.Container{
						{Name: "test", Image: "nginx", SecurityContext: &core.SecurityContext{Privileged: &isFalse}},
					},
					SecurityContext: &core.PodSecurityContext{},
				},
			},
			ExpectedStatus: &admission.AdmissionReviewStatus{
				Result: &metav1.Status{
					Code:    http.StatusForbidden,
					Message: "securityContext.runAsNonRoot=false : RunAsNonRoot must be true for container test",
					Reason:  metav1.StatusReasonForbidden,
					Status:  metav1.StatusFailure,
				},
			},
		},
	}
	newTestAdmissionWithSecurityContext().runTests(t, requests)
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
	newTestAdmissionWithSecurityContext().runTests(t, requests)
}

func TestAdmitHandlerWithOutNamespaceAnnotation(t *testing.T) {
	c := newTestAdmissionWithSecurityContext()
	c.service.client.CoreV1().Namespaces().Create(&v1.Namespace{
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
					Message: "spec.securityContext.hostNetwork=true : Host network is not allowed to be used",
					Reason:  metav1.StatusReasonForbidden,
					Status:  metav1.StatusFailure,
				},
			},
		},
	}
	c.runTests(t, requests)
}

func TestAdmitHandlerWithNamespaceAnnotation(t *testing.T) {
	c := newTestAdmissionWithSecurityContext()
	c.service.client.CoreV1().Namespaces().Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "default",
			Annotations: map[string]string{securitycontext.Annotation: "privileged"},
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
