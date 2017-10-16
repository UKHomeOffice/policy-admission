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

package namespaces

import (
	"errors"
	"regexp"
)

const (
	// Name is the name of the authorizer
	Name = "namespaces"
)

const (
	// TypeAnnotation indictes a annotation
	TypeAnnotation = "annotation"
	// TypeLabel indictes a label
	TypeLabel = "label"
)

// Attribute defines a required annotation
type Attribute struct {
	// Type indicates a label or annotation
	Type string
	// Required indicate the labels is required
	Required bool `yaml:"required" json:"required"`
	// Name is the name of thie field
	Name string `yaml:"name" json:"name"`
	// Validate is a regexp to apply
	Validate string `yaml:"validate" json:"valdiate"`
	// compiled is the compiled regex
	compiled *regexp.Regexp
}

// Config is the configuration for the service
type Config struct {
	// IgnoredNamespaces is a list namespaces to ignore
	IgnoreNamespaces []string `yaml:"ignore-namespaces" json:"ignore-namespaces"`
	// Attributes is a collection of attributes to validate the namespace
	Attributes []*Attribute `yaml:"attributes" json:"attributes"`
}

// NewDefaultConfig returns a default config
func NewDefaultConfig() *Config {
	return &Config{
		IgnoreNamespaces: []string{"kube-system", "kube-admission", "kube-public"},
	}
}

// IsValid checks the attribute it valid
func (a *Attribute) IsValid() error {
	if a.Name == "" {
		return errors.New("no name defined")
	}
	if a.Type == "" {
		return errors.New("no type defined")
	}
	switch a.Type {
	case TypeAnnotation:
	case TypeLabel:
	default:
		return errors.New("invalid type defined")
	}
	if !a.Required && a.Validate == "" {
		return errors.New("no validate defined")
	}
	if a.Validate != "" {
		if _, err := regexp.Compile(a.Validate); err != nil {
			return errors.New("invalid validator regex defined")
		}
	}

	return nil
}
