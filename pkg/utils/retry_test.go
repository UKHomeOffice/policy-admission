/*
Copyright 2017 Home Office All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable w or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRetryWithFailures(t *testing.T) {
	counter := 0
	fn := func() error {
		counter++
		return errors.New("a failure")
	}
	err := Retry(3, time.Millisecond*1, fn)
	assert.Error(t, err)
	assert.Equal(t, 3, counter)
}

func TestRetryWithOK(t *testing.T) {
	counter := 0
	fn := func() error {
		return nil
	}
	err := Retry(3, time.Millisecond*1, fn)
	assert.NoError(t, err)
	assert.Equal(t, 0, counter)
}
