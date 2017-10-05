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

import (
	"testing"
)

func TestConfigIsValid(t *testing.T) {
	cs := []struct {
		Config Config
		Error  string
	}{
		{
			Config: Config{},
			Error:  "no policies defined",
		},
	}

	for i, x := range cs {
		err := x.Config.isValid()
		if x.Error == "" && err != nil {
			t.Errorf("case %d, did not expect error: %s", i, err)
			continue
		}
		if x.Error != "" && err == nil {
			t.Errorf("case %d, expected error: %s", i, x.Error)
			continue
		}
		if x.Error != err.Error() {
			t.Errorf(`case %d, expected: "%s", got: "%s"`, i, x.Error, err)
		}
	}
}
