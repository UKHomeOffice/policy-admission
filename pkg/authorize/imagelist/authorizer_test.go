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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"

	"github.com/labstack/echo"
	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/fake"
	core "k8s.io/kubernetes/pkg/apis/core"
)

type imageListCheck struct {
	Containers     []core.Container
	InitContainers []core.Container
	Errors         field.ErrorList
}

func TestNew(t *testing.T) {
	c, err := New(nil)
	assert.NotNil(t, c)
	assert.NoError(t, err)
}

func TestAuthorizer(t *testing.T) {
	checks := map[string]imageListCheck{
		"checking the image are permitted": {
			Containers: []core.Container{
				{Image: "test:latest"},
			},
		},
		"checking the init containers image are permitted": {
			Containers: []core.Container{
				{Image: "test:latest"},
			},
		},
		"checking the multiple containers are cool": {
			Containers: []core.Container{
				{Image: "test:latest"},
				{Image: "test:latest"},
			},
		},
		"check the image is blocked": {
			Containers: []core.Container{
				{Image: "badimage:latest"},
			},
			Errors: field.ErrorList{
				{
					Field:    "spec.containers[0].image",
					BadValue: "badimage:latest",
					Type:     field.ErrorTypeInvalid,
					Detail:   "badimage:latest: denied by imagelist policy",
				},
			},
		},
		"check with multiple images the image is blocked": {
			Containers: []core.Container{
				{Image: "test:latest"},
				{Image: "badimage:latest"},
			},
			Errors: field.ErrorList{
				{
					Field:    "spec.containers[1].image",
					BadValue: "badimage:latest",
					Type:     field.ErrorTypeInvalid,
					Detail:   "badimage:latest: denied by imagelist policy",
				},
			},
		},
	}
	whitelist := []string{"test:latest", "rohith:latest"}

	newTestAuthorizer(t, nil, whitelist).runTests(t, checks)
}

func TestImageListDown(t *testing.T) {
	checks := map[string]imageListCheck{
		"checking the image are permitted": {
			Containers: []core.Container{
				{Image: "test:latest"},
			},
		},
	}
	c := newTestAuthorizer(t, nil, []string{"test:latest"})
	c.runTests(t, checks)

	u, _ := url.Parse(c.upstream.URL)
	hostname := fmt.Sprintf("%s", u.Host)

	checks = map[string]imageListCheck{
		"checking we get error when image service is down": {
			Containers: []core.Container{
				{Image: "bad_image:latest"},
			},
			Errors: field.ErrorList{
				{
					Field:  "imagelist",
					Type:   field.ErrorTypeInternal,
					Detail: fmt.Sprintf("communication failure with imagelist: Get http://%s/bad_image:latest: dial tcp %s: connect: connection refused", hostname, hostname),
				},
			},
		},
	}
	c.runTests(t, checks)
}

func TestCachedImage(t *testing.T) {
	checks := map[string]imageListCheck{
		"checking the image are permitted": {
			Containers: []core.Container{
				{Image: "test:latest"},
			},
		},
	}
	c := newTestAuthorizer(t, nil, []string{"test:latest"})
	c.runTests(t, checks)

	checks = map[string]imageListCheck{
		"checking the image result it read from the cache": {
			Containers: []core.Container{
				{Image: "test:latest"},
			},
		},
	}
	c.runTests(t, checks)
}

type testAuthorizer struct {
	config   *Config
	upstream *httptest.Server
	svc      api.Authorize
}

func newTestAuthorizer(t *testing.T, config *Config, imagelist []string) *testAuthorizer {
	if config == nil {
		config = NewDefaultConfig()
	}
	if len(imagelist) <= 0 {
		imagelist = newTestImageList()
	}

	engine := echo.New()
	engine.GET("/:name", func(c echo.Context) error {
		name := c.Param("name")
		for _, x := range imagelist {
			if name == x {
				return c.NoContent(http.StatusOK)
			}
		}

		return c.NoContent(http.StatusNotFound)
	})
	upstream := httptest.NewServer(engine)

	config.EndpointURL = upstream.URL
	config.Timeout = time.Duration(200 * time.Millisecond)

	c, err := New(config)
	require.NoError(t, err)

	return &testAuthorizer{
		config:   config,
		svc:      c,
		upstream: upstream,
	}
}

func (c *testAuthorizer) runTests(t *testing.T, checks map[string]imageListCheck) {
	defer c.upstream.Close()

	mcache := cache.New(1*time.Minute, 1*time.Minute)
	client := fake.NewSimpleClientset()

	for desc, check := range checks {
		pod := newTestPod()
		pod.Spec.InitContainers = check.InitContainers
		pod.Spec.Containers = check.Containers

		assert.Equal(t, check.Errors, c.svc.Admit(client, mcache, pod), "case: '%s' result not as expected", desc)
	}
}

func newTestImageList() []string {
	return []string{"nginx:latest", "test:latest"}
}

func newTestPod() *core.Pod {
	return &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "pod",
			Namespace:   "test",
			Annotations: map[string]string{},
		},
		Spec: core.PodSpec{},
	}
}
