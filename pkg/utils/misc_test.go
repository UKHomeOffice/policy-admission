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

package utils

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
)

func TestGetTRX(t *testing.T) {
	testID := "test"
	ctx := context.Background()
	ctx = SetTRX(ctx, testID)
	assert.Equal(t, testID, GetTRX(ctx))
}

func TestGetCachedResourceTimeout(t *testing.T) {
	c := newTestCache()
	o, err := GetCachedResource(nil, c, "test", time.Duration(10*time.Millisecond), time.Duration(1*time.Second),
		func(c kubernetes.Interface, key string) (interface{}, error) {
			time.Sleep(1 * time.Second)
			return nil, nil
		})
	assert.Nil(t, o)
	assert.Equal(t, ErrOperationTimeout, err)
}

func TestGetCachedResource(t *testing.T) {
	c := newTestCache()
	c.Set("test", "hello world", time.Duration(10*time.Second))
	o, err := GetCachedResource(nil, c, "test", time.Duration(10*time.Millisecond), time.Duration(1*time.Second),
		func(c kubernetes.Interface, key string) (interface{}, error) {
			return "should_not_return", nil
		})
	assert.NotNil(t, o)
	assert.NoError(t, err)
	assert.Equal(t, o, "hello world")
}

func TestGetCachedResourceFunction(t *testing.T) {
	c := newTestCache()
	o, err := GetCachedResource(nil, c, "test", time.Duration(10*time.Millisecond), time.Duration(1*time.Second),
		func(c kubernetes.Interface, key string) (interface{}, error) {
			return "hello world", nil
		})
	assert.NotNil(t, o)
	assert.NoError(t, err)
	assert.Equal(t, o, "hello world")
}

func TestNewHTTPServer(t *testing.T) {
	s, err := NewHTTPServer("127.0.0.1:8080", "", "")
	assert.NoError(t, err)
	assert.NotNil(t, s)
}

func TestContained(t *testing.T) {
	cs := []struct {
		List  []string
		Name  string
		Found bool
	}{
		{List: []string{"a", "b", "c"}},
		{List: []string{"a", "b", "c"}, Name: "a", Found: true},
		{List: []string{"a", "b", "c"}, Name: "b", Found: true},
		{List: []string{"fo*", "bar", "jar"}, Name: "foo", Found: true},
		{List: []string{"ca*", "dog", "rat"}, Name: "horse", Found: false},
	}
	for i, c := range cs {
		assert.Equal(t, c.Found, Contained(c.Name, c.List), "case %d, expected: %t, got: %t", i, c.Found, !c.Found)
	}
}

func newTestCache() *cache.Cache {
	return cache.New(time.Duration(1*time.Minute), time.Duration(1*time.Minute))
}
