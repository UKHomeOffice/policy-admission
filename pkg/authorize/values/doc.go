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

package values

import "regexp"

const (
	// Name is the name of the authorizer
	Name = "values"
	// Annotation is the namespace annotation used to control taints whitelist
	Annotation = "policy-admission.acp.homeoffice.gov.uk/" + Name
)

var (
	// AlphaRegex is a alpha regex
	AlphaRegex = regexp.MustCompile("^[a-zA-Z]*$")
	// NumericRegex is a numeric regex
	NumericRegex = regexp.MustCompile("^[0-9]*$")
	// TrafficRegex is a traffic spec i.e. 2m 2048k
	TrafficRegex = regexp.MustCompile("^[0-9]*[mkg]$")
)

var (
	filters = map[string]*regexp.Regexp{
		":alpha:":   AlphaRegex,
		":numeric:": NumericRegex,
		":traffic:": TrafficRegex,
	}
)

// Config is the configuration for the authorizer
type Config struct {
	// IgnoreNamespaces is list of namespace to
	IgnoreNamespaces []string `yaml:"ignored-namespaces" json:"ignored-namespaces"`
	// Matches is a collection of matches
	Matches []*Match `yaml:"matches" json:"matches"`
}

// Match defines a filter
type Match struct {
	// Namespaces is a list of namespaces this match should apply
	Namespaces []string `json:"namespaces,omitempty" yaml:"namespaces"`
	// Path is the value/s
	Path string `json:"path,omitempty" yaml:"path"`
	// KeyFilter is an additional filter if the value is a map
	KeyFilter string `json:"key-filter,omitempty" yaml:"key-filter"`
	// Required indicates the path MUST exist
	Required bool `json:"required,omitempty" yaml:"required"`
	// Value is a regex for the value
	Value string `json:"value,omitempty" yaml:"value"`
}

// NewDefaultConfig is the default configuration
func NewDefaultConfig() *Config {
	return &Config{
		IgnoreNamespaces: []string{"kube-system", "kube-public"},
	}
}
