/*
Copyright 2020 The Flux authors

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

package controller

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	flaggerv1 "github.com/fluxcd/flagger/pkg/apis/flagger/v1beta1"
	"github.com/fluxcd/flagger/pkg/canary"
)

// newHTTPClient builds the HTTP client used for webhook calls. When disableTls
// is set a fresh transport replaces the default one, so the default proxy and
// connection pooling settings no longer apply.
func newHTTPClient(retries int, timeout time.Duration, disableTls bool) *retryablehttp.Client {
	httpClient := retryablehttp.NewClient()
	httpClient.RetryMax = retries
	httpClient.Logger = nil
	httpClient.HTTPClient.Timeout = timeout
	// Keep the last response when the retries are exhausted so the status code
	// and body can still be reported instead of a generic "giving up" error.
	httpClient.ErrorHandler = retryablehttp.PassthroughErrorHandler

	if disableTls {
		httpClient.HTTPClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return httpClient
}

// webhookStatusError is returned when the webhook answered with a status code
// outside the accepted 2xx range. It lets callers distinguish an explicit
// rejection from a transport failure such as a timeout or an unreachable host.
type webhookStatusError struct {
	StatusCode int
	Body       string
}

func (e *webhookStatusError) Error() string {
	statusText := http.StatusText(e.StatusCode)
	if e.Body != "" {
		if statusText != "" {
			return fmt.Sprintf("request failed with status code %d (%s): %s", e.StatusCode, statusText, e.Body)
		}
		return fmt.Sprintf("request failed with status code %d: %s", e.StatusCode, e.Body)
	}
	if statusText != "" {
		return fmt.Sprintf("request failed with status code %d (%s)", e.StatusCode, statusText)
	}
	return fmt.Sprintf("request failed with status code %d", e.StatusCode)
}

// isWebhookStatusError reports whether the webhook reached the server and was
// rejected, as opposed to failing at the transport level.
func isWebhookStatusError(err error) bool {
	var statusErr *webhookStatusError
	return errors.As(err, &statusErr)
}

func callWebhook(webhook string, payload interface{}, timeout time.Duration, retries int, disableTls bool) error {
	payloadBin, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	hook, err := url.Parse(webhook)
	if err != nil {
		return err
	}

	httpClient := newHTTPClient(retries, timeout, disableTls)

	req, err := retryablehttp.NewRequest("POST", hook.String(), bytes.NewBuffer(payloadBin))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	r, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("error reading body: %s", err.Error())
	}

	// Any 2xx response is a pass. Servers commonly answer with 204 No Content
	// for an accepted gate check.
	if r.StatusCode < 200 || r.StatusCode > 299 {
		return &webhookStatusError{StatusCode: r.StatusCode, Body: strings.TrimSpace(string(b))}
	}

	return nil
}

// CallWebhook does an HTTP POST to an external service and returns an error if
// the response status code is outside the 2xx range or the request fails.
func CallWebhook(canary flaggerv1.Canary, phase flaggerv1.CanaryPhase, w flaggerv1.CanaryWebhook) error {
	payload := flaggerv1.CanaryWebhookPayload{
		Name:      canary.Name,
		Namespace: canary.Namespace,
		Phase:     phase,
		Checksum:  canaryChecksum(canary),
	}

	if w.Metadata != nil {
		payload.Metadata = *w.Metadata
	}

	timeout, err := webhookTimeout(w)
	if err != nil {
		return err
	}

	return callWebhook(w.URL, payload, timeout, w.Retries, w.DisableTLS)
}

func CallEventWebhook(r *flaggerv1.Canary, w flaggerv1.CanaryWebhook, message, eventtype string) error {
	t := time.Now()

	payload := flaggerv1.CanaryWebhookPayload{
		Name:      r.Name,
		Namespace: r.Namespace,
		Phase:     r.Status.Phase,
		Checksum:  canaryChecksum(*r),
		Metadata: map[string]string{
			"eventMessage": message,
			"eventType":    eventtype,
			"timestamp":    strconv.FormatInt(t.UnixNano()/1000000, 10),
		},
	}

	if w.Metadata != nil {
		for key, value := range *w.Metadata {
			if _, ok := payload.Metadata[key]; ok {
				continue
			}
			payload.Metadata[key] = value
		}
	}

	timeout, err := webhookTimeout(w)
	if err != nil {
		return err
	}

	return callWebhook(w.URL, payload, timeout, w.Retries, w.DisableTLS)
}

func canaryChecksum(c flaggerv1.Canary) string {
	canaryFields := struct {
		TrackedConfigs  *map[string]string
		LastAppliedSpec string
	}{
		c.Status.TrackedConfigs,
		c.Status.LastAppliedSpec,
	}

	return canary.ComputeHash(canaryFields)
}
