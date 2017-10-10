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
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/patrickmn/go-cache"
)

var (
	// ErrOperationTimeout indicated the operation timed out
	ErrOperationTimeout = errors.New("operation timeout")
)

// CacheFn is a cache return function, assuming the resource in not found in the cache
type CacheFn func(kubernetes.Interface, string) (interface{}, error)

// NewHttpServer creates and returns a new http server
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

// GetCachedResource is helper method used to retrieve an item from cache or grab and place it there
func GetCachedResource(client kubernetes.Interface, ca *cache.Cache, key string, timeout, expiration time.Duration, resourceFn CacheFn) (interface{}, error) {
	// @step: attempt to retrieve the resource from the cache
	resource, found := ca.Get(key)
	if found {
		return resource, nil
	}

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

// Contained checks if the string exists
func Contained(name string, whitelist []string) bool {
	for _, x := range whitelist {
		if x == name {
			return true
		}
	}

	return false
}
