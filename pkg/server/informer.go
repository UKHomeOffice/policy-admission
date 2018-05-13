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

package server

import (
	"context"
	"fmt"

	gocache "github.com/patrickmn/go-cache"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
)

type resourceInformer struct {
	// informer is the lister
	informer cache.SharedIndexInformer
	// prefix is the prefix to add to the cache with
	prefix string
	// store is the cache to add the resource to
	store *gocache.Cache
}

// newResourceInformer returns a new namespace controller
func newResourceInformer(informer cache.SharedIndexInformer, prefix string, store *gocache.Cache) (*resourceInformer, error) {
	return &resourceInformer{
		informer: informer,
		prefix:   prefix,
		store:    store,
	}, nil
}

// start is responsible for running the informing and updating the caches
func (c *resourceInformer) start(ctx context.Context) error {
	// @step: we create a informer
	c.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				c.store.Set(c.keyName(key), obj, 0)
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
				c.store.Set(c.keyName(key), obj, 0)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(newObj)
			if err == nil {
				c.store.Set(c.keyName(key), newObj, 0)
			}
		},
	})

	// @step: start the shared index informer
	stopCh := make(chan struct{}, 0)
	go c.informer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, c.informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("controller timed out waiting for caches to sync"))

		return fmt.Errorf("controller timed out waiting for cache sync")
	}

	// @step: wait for a signal to stop
	select {
	case <-ctx.Done():
		close(stopCh)
	}

	return nil
}

// keyName returns the name to add to the cache
func (c *resourceInformer) keyName(name string) string {
	return fmt.Sprintf("%s/%s", c.prefix, name)
}
