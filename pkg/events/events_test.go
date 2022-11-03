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
	"testing"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admission "k8s.io/api/admission/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fakeSink struct {
	count int
}

func (f *fakeSink) Send(*api.Event) error {
	f.count = f.count + 1

	return nil
}

func newFakeSink() *fakeSink {
	return &fakeSink{}
}

func newFakeEvent() *api.Event {
	return &api.Event{
		Detail: "test message",
		Review: &admission.AdmissionRequest{},
		Object: &core.Pod{
			ObjectMeta: metav1.ObjectMeta{
				UID: "test",
			},
		},
	}
}

func TestNew(t *testing.T) {
	m, err := New(1*time.Second, newFakeSink())
	assert.NoError(t, err)
	assert.NotNil(t, m)
}

func TestSend(t *testing.T) {
	f := newFakeSink()
	m, err := New(1*time.Second, f)
	require.NoError(t, err)

	m.Send(newFakeEvent())
	assert.Equal(t, 1, f.count)
}

func TestDuplicateEvent(t *testing.T) {
	f := newFakeSink()
	m, err := New(10*time.Second, f)
	require.NoError(t, err)
	m.Send(newFakeEvent())
	m.Send(newFakeEvent())
	assert.Equal(t, 1, f.count)
}

func TestDuplicateAllowed(t *testing.T) {
	f := newFakeSink()
	m, err := New(5*time.Millisecond, f)
	require.NoError(t, err)

	m.Send(newFakeEvent())
	m.Send(newFakeEvent())
	assert.Equal(t, 1, f.count)
	time.Sleep(50 * time.Millisecond)
	m.Send(newFakeEvent())
	assert.Equal(t, 2, f.count)
}
