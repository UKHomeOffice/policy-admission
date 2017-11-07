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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	admission "k8s.io/api/admission/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	core "k8s.io/kubernetes/pkg/api"
)

func TestDenialEventCreated(t *testing.T) {
	c := newTestAdmissionWithSecurityContext()
	c.service.config.EnableEvents = true
	c.service.config.Namespace = "test"

	requests := []request{
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
	}
	c.runTests(t, requests)

	events, err := c.service.client.CoreV1().Events("test").List(metav1.ListOptions{})
	assert.NoError(t, err)
	require.NotNil(t, events)
	assert.Equal(t, 1, len(events.Items))
}
