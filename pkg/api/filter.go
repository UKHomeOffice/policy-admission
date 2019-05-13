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
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Matched checks if the filter matches
func (f *Filter) Matched(kind metav1.GroupVersionKind, namespace *v1.Namespace) bool {
	if namespace != nil {
		// @step: check if the namespace if being ignored
		for _, x := range f.IgnoreNamespaces {
			if x == namespace.Name {
				return false
			}
		}

		// @check for any namespace labels
		if len(f.IgnoreNamespaceLabels) > 0 {
			filtered := func() bool {
				labels := namespace.GetLabels()
				for k, e := range f.IgnoreNamespaceLabels {
					value, exists := labels[k]
					if !exists {
						return false
					}
					// @check if anything is expected
					if e == "" {
						continue
					}
					if e != value {
						return false
					}
				}
				return true
			}()
			if filtered {
				return false
			}
		}
	}

	// @check if we are matching everything
	if f.Kind == FilterAll {
		return true
	}
	// @check the api group if set is the same
	if f.Group != "" && f.Group != kind.Group {
		return false
	}
	// @check the version if set
	if f.Version != "" && f.Version != kind.Version {
		return false
	}

	// @check the kind is the same
	return f.Kind == kind.Kind
}
