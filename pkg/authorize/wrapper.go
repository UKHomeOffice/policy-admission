/*
Copyright 2017 Home Office All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
	c.RLock()
	defer c.RUnlock()
	return c.authorizer.Name()
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package authorize

import (
	"sync"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
)

// wrapper is a reloadable authorization provider
type wrapper struct {
	sync.RWMutex

	// provider is actual authorizer
	provider api.Authorize
	// config is the path to the configuration file
	config string
}

// newWrapper creates and returns a new reloadable provider
func newWrapper(name, path string) (api.Authorize, error) {
	provider, err := newAuthorizer(name, path)
	if err != nil {
		return nil, err
	}
	w := &wrapper{provider: provider, config: path}

	if err := w.watchConfigChanges(); err != nil {
		return nil, err
	}

	return w, nil
}

// Admit makes a decision on the pod acceptance
func (c *wrapper) Admit(client kubernetes.Interface, namespace *v1.Namespace, object metav1.Object) field.ErrorList {
	c.RLock()
	defer c.RUnlock()
	return c.provider.Admit(client, namespace, object)
}

// Name is the name of the provider
func (c *wrapper) Name() string {
	return c.provider.Name()
}

// FilterOn return the filter for the provider
func (c *wrapper) FilterOn() api.Filter {
	c.RLock()
	defer c.RUnlock()
	return c.provider.FilterOn()
}

func (w *wrapper) watchConfigChanges() error {
	update, errors, _, err := utils.NewConfig(w.config).Watch()
	if err != nil {
		return err
	}
	// we wait for changes to the provider, reload and update
	go func() {
		for {
			select {
			case <-update:
				p, err := newAuthorizer(w.provider.Name(), w.config)
				if err == nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
						"name":  w.provider.Name(),
					}).Error("failed to create new authorizer on config change")

					break
				}
				w.update(p)
			case err := <-errors:
				log.WithFields(log.Fields{
					"error": err.Error(),
					"name":  w.provider.Name(),
				}).Error("recieved and error on config watcher")
			}
		}
	}()

	return nil
}

// update is responsible for updating the undelining provider
func (w *wrapper) update(provider api.Authorize) {
	w.Lock()
	defer w.Unlock()

	log.WithFields(log.Fields{
		"name": provider.Name(),
	}).Info("updating the provide with new config")

	w.provider = provider
}
