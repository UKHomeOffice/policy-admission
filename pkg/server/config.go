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
	"errors"
	"net/url"
)

// IsValid checks the configuration is valid
func (c *Config) IsValid() error {
	// @check the namespace is set if events have are enabled
	if c.EnableEvents && c.Namespace == "" {
		return errors.New("namespace must be defined when enabling events")
	}

	// @check the slack curation if required
	if c.SlackWebHook != "" {
		if _, err := url.Parse(c.SlackWebHook); err != nil {
			return err
		}
		if c.ClusterName == "" {
			return errors.New("cluster name not specified")
		}
	}

	return nil
}
