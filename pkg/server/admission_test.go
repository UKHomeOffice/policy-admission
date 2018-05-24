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
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/authorize/images"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admission "k8s.io/api/admission/v1beta1"
	authentication "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// request defines a fake review request
type request struct {
	Method string
	Pod    *core.Pod
	Review *admission.AdmissionReview
	Body   string
	URI    string

	ExpectedCode    int
	ExpectedContent string
	ExpectedStatus  *admission.AdmissionResponse
}

// testAdmission is a wrapper around a test admission server
type testAdmission struct {
	server  *httptest.Server
	service *Admission
}

func newTestImagesContextAuthorizer() api.Authorize {
	config := images.NewDefaultConfig()
	config.ImagePolicies = []string{"docker.io/*"}
	config.IgnoreNamespaces = []string{"kube-system", "ignored"}

	a, _ := images.New(config)
	return a
}

func newTestAdmissionWithImagesContext() *testAdmission {
	log.SetOutput(ioutil.Discard)
	c, _ := New(newTestConfig(), []api.Authorize{newTestImagesContextAuthorizer()})
	c.client = newTestKubernetesClient()

	return &testAdmission{server: httptest.NewServer(c.engine), service: c}
}

func newTestKubernetesClient() kubernetes.Interface {
	client := fake.NewSimpleClientset()

	for _, namespace := range []string{"test", "kube-system", "ignored"} {
		client.CoreV1().Namespaces().Create(&core.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespace},
		})
	}

	return client
}

func newTestConfig() *Config {
	return &Config{Listen: "127.0.0.1:8080", EnableMetrics: true}
}

// runTests performs a series of tests on the service
func (c *testAdmission) runTests(t *testing.T, requests []request) {
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
					APIVersion: "admission.k8s.io/v1beta1",
					Kind:       "AdmissionReview",
				},
				Request: &admission.AdmissionRequest{
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
			assert.Equal(t, x.ExpectedStatus, status.Response, "case %d: result not as expected", i)
		}
	}
}
