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

package events

import (
	sha "crypto/sha256"
	"encoding/base64"
	"errors"
	"path/filepath"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/utils"

	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

// manager is a state of the events
type manager struct {
	// rated is effectively being used as a rate limit of similar messages
	rated *cache.Cache
	// sinks is a collection of sinks to send the events
	sinks []api.Sink
}

// New creates and returns a manager for the events
func New(limit time.Duration, sinks ...api.Sink) (api.Sink, error) {
	if limit <= 0 {
		return nil, errors.New("rate limit must be greater then zero")
	}

	return &manager{
		rated: cache.New(limit, limit/2),
		sinks: sinks,
	}, nil
}

// Send is responsible for sending the messages into sink
func (m *manager) Send(event *api.Event) error {
	// @check we have everything
	if event.Detail == "" {
		return errors.New("no detail message")
	}
	if event.Review == nil {
		return errors.New("no admission review")
	}
	if event.Object == nil {
		return errors.New("no object")
	}

	// @step: generate a key used to index duplicate events .. object uid and message
	key := filepath.Join(event.Object.GetNamespace(), event.Detail)
	encoded := sha.Sum256([]byte(key))
	hash := base64.RawStdEncoding.EncodeToString(encoded[:])

	// @step: filter out duplicate messages
	if _, found := m.rated.Get(hash); found {
		log.WithFields(log.Fields{
			"detail":    event.Detail,
			"name":      event.Object.GetName(),
			"namespace": event.Object.GetNamespace(),
			"uid":       event.Object.GetUID(),
		}).Debug("found duplicate message, ignoring")

		return nil
	}

	// @step: add a entry into cache
	m.rated.SetDefault(hash, true)

	// @step: interate the sinks and send the messages
	for _, x := range m.sinks {
		err := utils.Retry(5, time.Second*3, func() error {
			return x.Send(event)
		})
		if err != nil {
			return err
		}
	}

	return nil
}
