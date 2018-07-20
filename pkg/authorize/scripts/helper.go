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

package scripts

import (
	"fmt"
	"strings"

	"github.com/robertkrimen/otto"
)

func inDomain(call otto.FunctionCall) otto.Value {
	hostname := call.Argument(0).String()
	domain := call.Argument(1).String()

	// @step: filter out any space in the domain name
	domain = strings.Replace(domain, " ", "", -1)

	// @check of the domain has a wildcard
	wildcard := strings.HasPrefix(domain, "*.")

	switch wildcard {
	case true:
		fqdn := fmt.Sprintf("%s.%s", strings.Split(hostname, ".")[0], strings.TrimPrefix(domain, "*."))
		if hostname == fqdn {
			return otto.TrueValue()
		}
	default:
		// @check there is an exact match between hostname and whitelist
		if hostname == domain {
			return otto.TrueValue()
		}
	}

	return otto.FalseValue()
}

func hasSuffix(call otto.FunctionCall) otto.Value {
	if strings.HasSuffix(call.Argument(0).String(), call.Argument(1).String()) {
		return otto.TrueValue()
	}

	return otto.FalseValue()
}

func hasPrefix(call otto.FunctionCall) otto.Value {
	if strings.HasPrefix(call.Argument(0).String(), call.Argument(1).String()) {
		return otto.TrueValue()
	}

	return otto.FalseValue()
}
