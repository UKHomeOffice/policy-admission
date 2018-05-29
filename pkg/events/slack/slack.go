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
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/UKHomeOffice/policy-admission/pkg/api"

	message "github.com/nlopes/slack"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type slackEvents struct {
	// the slack api client
	client *message.Client
	// channel is the channel to send the events
	channel string
	// name is the name of the kubernetes cluster
	name string
}

// New creates and returns a slack sink
func New(name, token, channel string) (api.Sink, error) {
	return &slackEvents{
		channel: channel,
		client:  message.New(token),
		name:    name,
	}, nil
}

// Send sends the event into slack
func (s *slackEvents) Send(o metav1.Object, detail string) error {
	params := message.PostMessageParameters{}
	params.Channel = s.channel
	params.Markdown = true

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var items []string

	items = append(items, "** Denial **")
	items = append(items, fmt.Sprintf("Cluster: %s", s.name))
	items = append(items, fmt.Sprintf("Namespace: %s", o.GetNamespace()))
	items = append(items, fmt.Sprintf("Message: %s", detail))
	text := strings.Join(items, "\n")

	_, _, err := s.client.PostMessageContext(ctx, s.channel, text, params)

	return err
}
