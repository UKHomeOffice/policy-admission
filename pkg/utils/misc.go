/*
Copyright 2017 Home Office All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable w or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"context"
	"crypto/tls"
	"errors"
	"math/rand"
	"net/http"
	"path/filepath"
	"regexp"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/patrickmn/go-cache"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var (
	// ErrOperationTimeout indicated the operation timed out
	ErrOperationTimeout = errors.New("operation timeout")
	// letterBytes used for a random string
	letterBytes = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// CacheFn is a cache return function, assuming the resource in not found in the cache
type CacheFn func(kubernetes.Interface, string) (interface{}, error)

// GetAnnotation returns a formatted annotation
func GetAnnotation(names ...string) string {
	return filepath.Join(names...)
}

// NewHTTPServer creates and returns a new http server
func NewHTTPServer(listen, cert, key string) (*http.Server, error) {
	server := &http.Server{
		Addr:         listen,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  5 * time.Second,
	}

	if key != "" && cert != "" {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.NoClientCert}

		cert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		server.TLSConfig = tlsConfig
	}

	return server, nil
}

// Random returns a random string
func Random(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}

	return string(b)
}

// TRX is a request unique id
type TRX string

// TRXName is the name in the context
const TRXName TRX = "uuid"

// GetTRX returns the request transaction id from the context
func GetTRX(c context.Context) string {
	v := c.Value(TRXName)
	if v == nil {
		return ""
	}

	return v.(string)
}

// SetTRX sets the uuid of the context
func SetTRX(c context.Context, id string) context.Context {
	return context.WithValue(c, TRXName, id)
}

// GetCacheKey returns a join key
func GetCacheKey(names ...string) string {
	return filepath.Join(names...)
}

// GetCachedNamespace is responsible for retrieving the namespace via the api
func GetCachedNamespace(client kubernetes.Interface, mcache *cache.Cache, name string) (*core.Namespace, error) {
	cached, err := GetCachedResource(client, mcache, GetCacheKey(api.NamespaceCacheKey, name), time.Duration(1*time.Minute), time.Duration(10*time.Minute),
		func(client kubernetes.Interface, keyname string) (interface{}, error) {
			resource, err := client.CoreV1().Namespaces().Get(name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}

			return resource, nil
		})
	if err != nil {
		return nil, err
	}
	namespace := cached.(*core.Namespace)

	return namespace, nil
}

// GetCachedResource is helper method used to retrieve an item from cache or grab and place it there
func GetCachedResource(client kubernetes.Interface, ca *cache.Cache, key string, timeout, expiration time.Duration, resourceFn CacheFn) (interface{}, error) {
	// @step: attempt to retrieve the resource from the cache
	resource, found := ca.Get(key)
	if found {
		cacheHitMetric.WithLabelValues("miss").Inc()
		return resource, nil
	}
	cacheHitMetric.WithLabelValues("hit").Inc()

	tm := time.Now()
	defer cacheLatencyMetric.Observe(time.Since(tm).Seconds())

	// @step: else we need to grab the resource method
	errorCh := make(chan error, 0)
	doneCh := make(chan interface{}, 0)

	go func() {
		resource, err := resourceFn(client, key)
		if err != nil {
			errorCh <- err
			return
		}
		if expiration > 0 {
			ca.Add(key, resource, expiration)
		}
		doneCh <- resource
	}()

	// @step: we wait for either an error, a timeout or successful resource
	select {
	case err := <-errorCh:
		return nil, err
	case resource := <-doneCh:
		return resource, nil
	case <-time.After(timeout):
		return nil, ErrOperationTimeout
	}
}

// Contained checks if the string exist supports regexs
func Contained(name string, whitelist []string) bool {
	for _, x := range whitelist {
		if m, _ := regexp.MatchString(x, name); m {
			return true
		}
	}

	return false
}
