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

package authorize

import (
	"errors"
	"fmt"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
	"github.com/UKHomeOffice/policy-admission/pkg/authorize/domains"
	"github.com/UKHomeOffice/policy-admission/pkg/authorize/imagelist"
	"github.com/UKHomeOffice/policy-admission/pkg/authorize/images"
	"github.com/UKHomeOffice/policy-admission/pkg/authorize/kubecertmanager"
	"github.com/UKHomeOffice/policy-admission/pkg/authorize/scripts"
	"github.com/UKHomeOffice/policy-admission/pkg/authorize/services"
	"github.com/UKHomeOffice/policy-admission/pkg/authorize/tolerations"
	"github.com/UKHomeOffice/policy-admission/pkg/authorize/values"
)

// New creates and returns a provider
func New(name, path string, reloadable bool) (api.Authorize, error) {
	if !reloadable {
		return newAuthorizer(name, path)
	}

	return newWrapper(name, path)
}

// newAuthorizer creates a new authorizer by name
func newAuthorizer(name, path string) (api.Authorize, error) {
	switch name {
	case domains.Name:
		return domains.NewFromFile(path)
	case images.Name:
		return images.NewFromFile(path)
	case imagelist.Name:
		return imagelist.NewFromFile(path)
	case kubecertmanager.Name:
		return kubecertmanager.NewFromFile(path)
	case "namespaces":
		return nil, fmt.Errorf("namespaces has been deprecated in favour of scripts or values")
	case scripts.Name:
		return scripts.NewFromFile(path)
	case services.Name:
		return services.NewFromFile(path)
	case tolerations.Name:
		return tolerations.NewFromFile(path)
	case values.Name:
		return values.NewFromFile(path)
	default:
		return nil, errors.New("unsupported authorizer")
	}
}
