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

package slack

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"
)

var client = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	},
}

type slackEvents struct {
	// name is the name of the kubernetes cluster
	name string
	// webhook is the url to send the events
	webhook string
}

// New creates and returns a slack sink
func New(cluster, webhook string) (api.Sink, error) {
	if _, err := url.Parse(webhook); err != nil {
		return nil, err
	}

	return &slackEvents{name: cluster, webhook: webhook}, nil
}

// Send sends the event into slack
func (s *slackEvents) Send(event *api.Event) error {
	message := &messagePayload{
		Text:     "The attached resource has denied",
		Username: "policy-admission",
		Attachments: []*attachment{
			{
				Color:     "danger",
				TimeStamp: time.Now().Unix(),
				Fields: []*attachmentField{
					{
						Title: "Detail",
						Value: event.Detail,
						Short: false,
					},
					{
						Title: "Cluster",
						Value: s.name,
						Short: true,
					},
					{
						Title: "Kind",
						Value: event.Review.Kind.Kind,
						Short: true,
					},
					{
						Title: "Name",
						Value: event.Object.GetName(),
						Short: true,
					},
					{
						Title: "Namespace",
						Value: event.Object.GetNamespace(),
						Short: true,
					},
					{
						Title: "Username",
						Value: event.Review.UserInfo.Username,
						Short: true,
					},
				},
			},
		},
	}

	encoded, err := json.Marshal(message)
	if err != nil {
		return err
	}

	resp, err := client.Post(s.webhook, "application/json", bytes.NewReader(encoded))
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		status, _ := ioutil.ReadAll(resp.Body)

		return errors.New(string(status))
	}

	return nil
}
