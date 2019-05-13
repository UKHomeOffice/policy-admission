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

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func makeTestNamespace(name string, labels map[string]string) *v1.Namespace {
	return &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func TestIsFiltered(t *testing.T) {
	cs := []struct {
		Expected  bool
		Filter    Filter
		Kind      metav1.GroupVersionKind
		Namespace *v1.Namespace
	}{
		{
			Filter:   Filter{Kind: FilterPods},
			Kind:     metav1.GroupVersionKind{Kind: FilterPods, Group: "v1"},
			Expected: true,
		},
		{
			Filter:    Filter{Kind: FilterPods, IgnoreNamespaces: []string{"test"}},
			Kind:      metav1.GroupVersionKind{Kind: FilterPods, Group: "v1"},
			Namespace: makeTestNamespace("test", nil),
			Expected:  false,
		},
		{
			Filter:    Filter{Kind: FilterPods, IgnoreNamespaces: []string{"test"}},
			Kind:      metav1.GroupVersionKind{Kind: FilterPods, Group: "v1"},
			Namespace: makeTestNamespace("test1", nil),
			Expected:  true,
		},
		{
			Filter:    Filter{Kind: FilterPods, IgnoreNamespaces: []string{"test"}, IgnoreNamespaceLabels: map[string]string{"skip": "me"}},
			Kind:      metav1.GroupVersionKind{Kind: FilterPods, Group: "v1"},
			Namespace: makeTestNamespace("test1", map[string]string{"skip": "me"}),
			Expected:  false,
		},
		{
			Filter:    Filter{Kind: FilterPods, IgnoreNamespaces: []string{"test"}, IgnoreNamespaceLabels: map[string]string{"skip": "me"}},
			Kind:      metav1.GroupVersionKind{Kind: FilterPods, Group: "v1"},
			Namespace: makeTestNamespace("test1", map[string]string{"skip": "nothing"}),
			Expected:  true,
		},
		{
			Filter:    Filter{Kind: FilterPods, IgnoreNamespaces: []string{"test"}, IgnoreNamespaceLabels: map[string]string{"skip": "me", "skip1": "true"}},
			Kind:      metav1.GroupVersionKind{Kind: FilterPods, Group: "v1"},
			Namespace: makeTestNamespace("test1", map[string]string{"skip": "me"}),
			Expected:  true,
		},
		{
			Filter:    Filter{Kind: FilterPods, IgnoreNamespaces: []string{"test"}, IgnoreNamespaceLabels: map[string]string{"skip": "me", "skip1": "true"}},
			Kind:      metav1.GroupVersionKind{Kind: FilterPods, Group: "v1"},
			Namespace: makeTestNamespace("test1", map[string]string{"skip": "me", "skip1": "true"}),
			Expected:  false,
		},
		{
			Filter:   Filter{Kind: FilterPods},
			Kind:     metav1.GroupVersionKind{Kind: FilterPods},
			Expected: true,
		},
		{
			Filter:   Filter{Kind: "Issuer", Group: "certmanager.k8s.io"},
			Kind:     metav1.GroupVersionKind{Kind: "Issuer"},
			Expected: false,
		},
		{
			Filter:   Filter{Kind: "Issuer", Group: "certmanager.k8s.io"},
			Kind:     metav1.GroupVersionKind{Kind: "Issuer", Group: "certmanager.k8s.io"},
			Expected: true,
		},
		{
			Filter: Filter{Kind: "Issuer", Group: "certmanager.k8s.io", Version: "alphav1"},
			Kind:   metav1.GroupVersionKind{Kind: "Issuer", Group: "certmanager.k8s.io"},
		},
		{
			Filter:   Filter{Kind: "Issuer", Group: "certmanager.k8s.io", Version: "alphav1"},
			Kind:     metav1.GroupVersionKind{Kind: "Issuer", Group: "certmanager.k8s.io", Version: "alphav1"},
			Expected: true,
		},
	}
	for i, c := range cs {
		matched := c.Filter.Matched(c.Kind, c.Namespace)
		assert.Equal(t, c.Expected, matched, "case %d, expected: %t but got: %t", i, c.Expected, matched)
	}
}
