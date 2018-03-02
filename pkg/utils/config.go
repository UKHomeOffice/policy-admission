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

package utils

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"path"

	"github.com/fsnotify/fsnotify"
	"github.com/ghodss/yaml"
)

// Config is the quick wrapper to provide reloadable configuration
type Config struct {
	filename string
}

// NewConfig returns a new configuration
func NewConfig(filename string) *Config {
	return &Config{filename: filename}
}

// Read is responsible for reading in the configuration
func (c *Config) Read(data interface{}) error {
	content, err := ioutil.ReadFile(c.filename)
	if err != nil {
		return err
	}

	switch path.Ext(c.filename) {
	case ".yaml":
		fallthrough
	case ".yml":
		err = yaml.Unmarshal(content, data)
	case ".json":
		err = json.Unmarshal(content, data)
	default:
		return errors.New("unsupported file format")
	}

	return err
}

// Watch starts watching the configu
func (c *Config) Watch() (chan bool, chan error, chan bool, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, nil, nil, err
	}

	if err := watcher.Add(path.Dir(c.filename)); err != nil {
		return nil, nil, nil, err
	}

	errorsCh := make(chan error, 5)
	stopCh := make(chan bool, 0)
	updateCh := make(chan bool, 5)

	go func() {
		for {
			select {
			case err := <-watcher.Errors:
				go func() {
					errorsCh <- err
				}()
			case event := <-watcher.Events:
				c.handleFileEvent(event, updateCh)
			case <-stopCh:
				return
			}
		}
	}()

	return updateCh, errorsCh, stopCh, nil
}

// handleFileEvent is responsible for handling the file changes if any
func (c *Config) handleFileEvent(event fsnotify.Event, client chan bool) {
	if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
		// @check this is related to our configration file
		if event.Name != c.filename {
			return
		}
		// @step: send a event upstream to client
		go func() {
			client <- true
		}()
	}
}
