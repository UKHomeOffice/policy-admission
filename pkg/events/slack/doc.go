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

// messagePayload is the payload to the slack webhook
type messagePayload struct {
	Attachments []*attachment `json:"attachments,omitempty"`
	Channel     string        `json:"channel,omitempty"`
	IconEmoji   string        `json:"icon_emoji,omitempty"`
	IconURL     string        `json:"icon_url,omitempty"`
	LinkNames   string        `json:"link_names,omitempty"`
	Text        string        `json:"text,omitempty"`
	UnfurlLinks bool          `json:"unfurl_links,omitempty"`
	Username    string        `json:"username,omitempty"`
}

type attachment struct {
	AuthorIcon    string             `json:"author_icon,omitempty"`
	AuthorLink    string             `json:"author_link,omitempty"`
	AuthorName    string             `json:"author_name,omitempty"`
	AuthorSubname string             `json:"author_subname,omitempty"`
	Color         string             `json:"color,omitempty"`
	Fallback      string             `json:"fallback"`
	Fields        []*attachmentField `json:"fields,omitempty"`
	Footer        string             `json:"footer,omitempty"`
	FooterIcon    string             `json:"footer_icon,omitempty"`
	ImageURL      string             `json:"image_url,omitempty"`
	MarkdownIn    []string           `json:"mrkdwn_in,omitempty"`
	Pretext       string             `json:"pretext,omitempty"`
	Text          string             `json:"text"`
	ThumbURL      string             `json:"thumb_url,omitempty"`
	TimeStamp     int64              `json:"ts,omitempty"`
	Title         string             `json:"title,omitempty"`
	TitleLink     string             `json:"title_link,omitempty"`
}

type attachmentField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}
