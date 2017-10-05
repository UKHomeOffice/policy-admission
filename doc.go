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

package main

import "errors"

const (
	// AdmissionControllerName is the name we register as
	AdmissionControllerName = "policy-admission.acp.homeoffice.gov.uk"
	// SecurityPolicyAnnotation is the annotation which controls policy you can use
	SecurityPolicyAnnotation = "policy-admission.acp.homeoffice.gov.uk/policy"
	// TaintsWhitelistAnnotation is the annotation which controls policy you can use
	TaintsWhitelistAnnotation = "policy-admission.acp.homeoffice.gov.uk/taints"
)

var (
	// Version is the version of the service
	Version = "v0.0.1"
	// GitSHA is the git sha this was built off
	GitSHA = "unknown"
)

// Config is the configuration for the service
type Config struct {
	// Listen is the interface we are listening on
	Listen string `yaml:"listen"`
	// TLSKey is the path to a private key
	TLSKey string `yaml:"tls-key"`
	// TLSCert is the path to a certificate
	TLSCert string `yaml:"tls-cert"`
	// Policies is the path to the security policy file
	Policies string `yaml:"policies"`
	// WatchConfig indicates we should reload the policy config
	WatchConfig bool `yaml:"watch-config"`
}

// isValid is resposible for checking the configuration
func (c *Config) isValid() error {
	if c.Listen == "" {
		return errors.New("no interface specified")
	}

	return nil
}
