/*
Copyright 2025 The Flux authors

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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	flaggerv1 "github.com/fluxcd/flagger/pkg/apis/flagger/v1beta1"
	"github.com/fluxcd/flagger/pkg/canary"
	"github.com/fluxcd/flagger/pkg/metrics"
	"github.com/fluxcd/flagger/pkg/notifier"
)

// spyNotifier records the alerts the controller would send.
type spyNotifier struct {
	messages []string
}

func (s *spyNotifier) Post(workload string, namespace string, message string, fields []notifier.Field, severity string) error {
	s.messages = append(s.messages, message)
	return nil
}

// fakeHookController records the status updates made by hooks. Only the methods
// used by the hook runners are implemented.
type fakeHookController struct {
	canary.Controller

	phaseChanges  []flaggerv1.CanaryPhase
	failedChecks  int
	failedUpdates int
	iterations    int
}

func (f *fakeHookController) SetStatusPhase(_ *flaggerv1.Canary, phase flaggerv1.CanaryPhase) error {
	f.phaseChanges = append(f.phaseChanges, phase)
	return nil
}

func (f *fakeHookController) SetStatusFailedChecks(_ *flaggerv1.Canary, val int) error {
	f.failedChecks = val
	f.failedUpdates++
	return nil
}

func (f *fakeHookController) SetStatusIterations(_ *flaggerv1.Canary, val int) error {
	f.iterations = val
	return nil
}

// decodeJSON decodes a JSON request body.
func decodeJSON(body io.Reader, v interface{}) error {
	return json.NewDecoder(body).Decode(v)
}

// recordedWebhook is one request received by the fake webhook service.
type recordedWebhook struct {
	path  string
	phase flaggerv1.CanaryPhase
}

// webhookRecorder serves the fake responses used by the contract test.
type webhookRecorder struct {
	mu       sync.Mutex
	requests []recordedWebhook
}

func (r *webhookRecorder) recorded() []recordedWebhook {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedWebhook(nil), r.requests...)
}

func (r *webhookRecorder) phases() []flaggerv1.CanaryPhase {
	var phases []flaggerv1.CanaryPhase
	for _, req := range r.recorded() {
		phases = append(phases, req.phase)
	}
	return phases
}

// responseCase describes a server answer and whether the hook should accept it.
type responseCase struct {
	name         string
	status       int
	body         string
	timeout      string
	refused      bool
	wantAccepted bool
}

func (rc responseCase) handler(rec *webhookRecorder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var payload flaggerv1.CanaryWebhookPayload
		if err := decodeJSON(r.Body, &payload); err == nil {
			rec.mu.Lock()
			rec.requests = append(rec.requests, recordedWebhook{path: r.URL.Path, phase: payload.Phase})
			rec.mu.Unlock()
		}
		if rc.timeout != "" {
			time.Sleep(200 * time.Millisecond)
		}
		if rc.status == 0 {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(rc.status)
		}
		if rc.body != "" {
			_, _ = w.Write([]byte(rc.body))
		}
	}
}

func newHookTestController() (*Controller, *spyNotifier, chan string) {
	events := make(chan string, 256)
	spy := &spyNotifier{}
	ctrl := &Controller{
		logger:        zap.S(),
		eventRecorder: record.NewFakeRecorder(256),
		recorder:      metrics.NewRecorder(controllerAgentName, false),
		notifier:      spy,
	}
	// Drain the fake recorder into the returned channel so tests can inspect
	// the emitted events.
	if fr, ok := ctrl.eventRecorder.(*record.FakeRecorder); ok {
		go func() {
			for ev := range fr.Events {
				events <- ev
			}
		}()
	}
	return ctrl, spy, events
}

func newHookTestCanary(hookType flaggerv1.HookType, hooks ...flaggerv1.CanaryWebhook) *flaggerv1.Canary {
	for i := range hooks {
		if hooks[i].Name == "" {
			hooks[i].Name = fmt.Sprintf("%s-%d", hookType, i)
		}
		if hooks[i].Type == "" && hookType != "" {
			hooks[i].Type = hookType
		}
	}
	return &flaggerv1.Canary{
		ObjectMeta: metav1.ObjectMeta{Name: "podinfo", Namespace: "default"},
		Spec: flaggerv1.CanarySpec{
			TargetRef: flaggerv1.LocalObjectReference{Name: "podinfo"},
			Analysis: &flaggerv1.CanaryAnalysis{
				Iterations: 10,
				Webhooks:   hooks,
			},
		},
		Status: flaggerv1.CanaryStatus{Phase: flaggerv1.CanaryPhaseProgressing},
	}
}

// runHooks invokes the runner belonging to a contract row and reports whether
// the analysis may continue.
func runHooks(t *testing.T, ctrl *Controller, contract webhookContract, hookCtrl *fakeHookController,
	canary *flaggerv1.Canary, phase flaggerv1.CanaryPhase) bool {
	t.Helper()
	switch contract.Type {
	case flaggerv1.ConfirmRolloutHook:
		return ctrl.runConfirmRolloutHooks(canary, hookCtrl)
	case flaggerv1.PreRolloutHook:
		return ctrl.runPreRolloutHooks(canary, hookCtrl)
	case flaggerv1.RolloutHook:
		return ctrl.runRolloutHooks(canary, hookCtrl)
	case flaggerv1.ConfirmTrafficIncreaseHook:
		return ctrl.runConfirmTrafficIncreaseHooks(canary)
	case flaggerv1.ConfirmPromotionHook:
		return ctrl.runConfirmPromotionHooks(canary, hookCtrl)
	case flaggerv1.PostRolloutHook:
		return ctrl.runPostRolloutHooks(canary, phase)
	case flaggerv1.RollbackHook:
		return ctrl.runRollbackHooks(canary, phase)
	default:
		t.Fatalf("no runner for hook type %q", contract.Type)
		return false
	}
}

var webhookResponseCases = []responseCase{
	{name: "200 with body", status: http.StatusOK, body: "ok", wantAccepted: true},
	{name: "204 no content", status: http.StatusNoContent, wantAccepted: true},
	{name: "203 non-authoritative", status: http.StatusNonAuthoritativeInfo, wantAccepted: true},
	{name: "200 empty body", status: http.StatusOK, wantAccepted: true},
	{name: "500 with body", status: http.StatusInternalServerError, body: "denied by policy", wantAccepted: false},
	{name: "500 empty body", status: http.StatusInternalServerError, wantAccepted: false},
	{name: "timeout", timeout: "10ms", status: http.StatusOK, wantAccepted: false},
	{name: "connection refused", refused: true, wantAccepted: false},
}

// TestWebhookContractPerType drives every contract row against every server
// response and asserts the documented consequences. The expectations are
// derived from the contract row itself, so the test fails when code and table
// disagree.
func TestWebhookContractPerType(t *testing.T) {
	for _, contract := range webhookContracts {
		if contract.Type == flaggerv1.EventHook {
			// Event hooks are dispatched by the event recorder, not by a hook
			// runner; covered by TestWebhookContractEventHook.
			continue
		}
		contract := contract
		for _, rc := range webhookResponseCases {
			if contract.Type == flaggerv1.RollbackHook && rc.refused {
				// Covered separately: an unreachable rollback hook must warn.
				continue
			}
			t.Run(string(contract.Type)+"/"+rc.name, func(t *testing.T) {
				rec := &webhookRecorder{}
				server := httptest.NewServer(rc.handler(rec))
				url := server.URL
				if rc.refused {
					server.Close()
				} else {
					defer server.Close()
				}

				timeout := "2s"
				if rc.timeout != "" {
					timeout = rc.timeout
				}
				hook := flaggerv1.CanaryWebhook{Type: contract.Type, Name: "hook", URL: url, Timeout: timeout}
				canary := newHookTestCanary(contract.Type, hook)

				ctrl, spy, events := newHookTestController()
				hookCtrl := &fakeHookController{}

				phase := flaggerv1.CanaryPhaseProgressing
				if contract.Type == flaggerv1.PostRolloutHook {
					phase = flaggerv1.CanaryPhaseSucceeded
				}

				ok := runHooks(t, ctrl, contract, hookCtrl, canary, phase)

				// With a single hook the runner's return value equals the
				// server answer for every type: "the cycle may continue" for
				// gating hooks, "all hooks succeeded" for post-rollout and "a
				// rollback was requested" for the rollback hook.
				assert.Equal(t, rc.wantAccepted, ok)

				if rc.wantAccepted {
					assert.Empty(t, hookCtrl.phaseChanges, "a passing hook must not change the phase")
					assert.Zero(t, hookCtrl.failedUpdates, "a passing hook must not touch the failure budget")
					assert.Empty(t, spy.messages, "a passing hook must not alert")
				} else {
					if contract.FailurePhase != "" {
						require.Equal(t, []flaggerv1.CanaryPhase{contract.FailurePhase}, hookCtrl.phaseChanges)
					} else {
						assert.Empty(t, hookCtrl.phaseChanges)
					}

					if contract.CountsFailure {
						assert.Equal(t, 1, hookCtrl.failedUpdates)
						assert.Equal(t, 1, hookCtrl.failedChecks)
					} else {
						assert.Zero(t, hookCtrl.failedUpdates, "failure must not count towards the failure budget")
					}

					if contract.FailureAlert {
						require.Len(t, spy.messages, 1)
						assert.Equal(t, contract.alertMessage, spy.messages[0])
					} else {
						assert.Empty(t, spy.messages)
					}

					if contract.countFailureMetric {
						got := testutil.ToFloat64(ctrl.recorder.GetWebhookFailuresMetric().
							WithLabelValues("podinfo", "default", string(contract.Type)))
						assert.Equal(t, float64(1), got)
					}
				}

				// Payload phase.
				expectedPhases := []flaggerv1.CanaryPhase{contract.PayloadPhase}
				switch contract.Type {
				case flaggerv1.ConfirmRolloutHook, flaggerv1.RollbackHook, flaggerv1.EventHook:
					expectedPhases = []flaggerv1.CanaryPhase{canary.Status.Phase}
				case flaggerv1.PostRolloutHook:
					expectedPhases = []flaggerv1.CanaryPhase{phase}
				}
				if rc.refused {
					assert.Empty(t, rec.phases(), "no request reaches a refused server")
				} else {
					assert.Equal(t, expectedPhases, rec.phases())
				}

				// Events.
				gotEvents := drainEvents(events)
				if rc.wantAccepted && contract.emitPassedEvent {
					assert.Contains(t, strings.Join(gotEvents, "\n"), fmt.Sprintf("%s check hook passed", contract.checkLabel))
				}
				if !rc.wantAccepted && contract.Type == flaggerv1.PostRolloutHook {
					assert.Contains(t, strings.Join(gotEvents, "\n"), "Post-rollout hook hook failed")
				}
				if !rc.wantAccepted && contract.inverted && rc.status >= 400 {
					assert.Contains(t, strings.Join(gotEvents, "\n"), "Rollback hook hook not signaling a rollback")
				}
			})
		}
	}
}

func TestWebhookContractRollbackUnreachableWarns(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()

	canary := newHookTestCanary(flaggerv1.RollbackHook,
		flaggerv1.CanaryWebhook{Type: flaggerv1.RollbackHook, Name: "rollback", URL: url, Timeout: "1s"})
	ctrl, spy, events := newHookTestController()

	require.False(t, ctrl.runRollbackHooks(canary, canary.Status.Phase))
	assert.Empty(t, spy.messages, "rollback hooks never alert")
	assert.Contains(t, strings.Join(drainEvents(events), "\n"),
		"Rollback hook rollback is unreachable, treating it as not signaling a rollback")
}

func TestWebhookContractConfirmGatesAlertOnce(t *testing.T) {
	for _, hookType := range []flaggerv1.HookType{flaggerv1.ConfirmRolloutHook, flaggerv1.ConfirmPromotionHook} {
		t.Run(string(hookType), func(t *testing.T) {
			contract := mustWebhookContract(hookType)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			}))
			defer server.Close()

			canary := newHookTestCanary(hookType,
				flaggerv1.CanaryWebhook{Type: hookType, Name: "gate", URL: server.URL, Timeout: "2s"})
			ctrl, spy, events := newHookTestController()
			hookCtrl := &fakeHookController{}

			require.False(t, runHooks(t, ctrl, contract, hookCtrl, canary, canary.Status.Phase))
			require.Len(t, hookCtrl.phaseChanges, 1)
			require.Len(t, spy.messages, 1)
			firstEvents := drainEvents(events)
			require.NotEmpty(t, firstEvents)

			// Second failure while already waiting: no phase change, no alert.
			canary.Status.Phase = contract.FailurePhase
			require.False(t, runHooks(t, ctrl, contract, hookCtrl, canary, canary.Status.Phase))
			assert.Len(t, hookCtrl.phaseChanges, 1, "phase is only set on the transition")
			assert.Len(t, spy.messages, 1, "alert is only sent on the transition")
			assert.Empty(t, drainEvents(events))
		})
	}
}

func TestWebhookContractMuteAlert(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	hooks := []flaggerv1.CanaryWebhook{
		{Type: flaggerv1.ConfirmRolloutHook, Name: "gated", URL: server.URL, Timeout: "2s", MuteAlert: true},
	}
	canary := newHookTestCanary(flaggerv1.ConfirmRolloutHook, hooks...)
	ctrl, spy, _ := newHookTestController()

	require.False(t, ctrl.runConfirmRolloutHooks(canary, &fakeHookController{}))
	assert.Empty(t, spy.messages, "muteAlert suppresses the gate alert")
}

func TestWebhookContractPreRolloutFailureBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	canary := newHookTestCanary(flaggerv1.PreRolloutHook,
		flaggerv1.CanaryWebhook{Type: flaggerv1.PreRolloutHook, Name: "test", URL: server.URL, Timeout: "2s"})
	canary.Status.FailedChecks = 3
	ctrl, _, _ := newHookTestController()
	hookCtrl := &fakeHookController{}

	require.False(t, ctrl.runPreRolloutHooks(canary, hookCtrl))
	assert.Equal(t, 4, hookCtrl.failedChecks)
}

func TestWebhookContractConfirmPromotionIterations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	canary := newHookTestCanary(flaggerv1.ConfirmPromotionHook,
		flaggerv1.CanaryWebhook{Type: flaggerv1.ConfirmPromotionHook, Name: "gate", URL: server.URL, Timeout: "2s"})
	canary.Status.Phase = flaggerv1.CanaryPhaseWaitingPromotion
	ctrl, spy, _ := newHookTestController()
	hookCtrl := &fakeHookController{}

	require.False(t, ctrl.runConfirmPromotionHooks(canary, hookCtrl))
	assert.Equal(t, canary.GetAnalysis().Iterations-1, hookCtrl.iterations)
	assert.Empty(t, hookCtrl.phaseChanges)
	assert.Empty(t, spy.messages)
}

func TestWebhookContractOrdering(t *testing.T) {
	t.Run("short-circuit stops after the first failure", func(t *testing.T) {
		for _, hookType := range []flaggerv1.HookType{
			flaggerv1.ConfirmRolloutHook,
			flaggerv1.PreRolloutHook,
			flaggerv1.RolloutHook,
			flaggerv1.ConfirmTrafficIncreaseHook,
			flaggerv1.ConfirmPromotionHook,
		} {
			hookType := hookType
			t.Run(string(hookType), func(t *testing.T) {
				rec := &webhookRecorder{}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var payload flaggerv1.CanaryWebhookPayload
					require.NoError(t, decodeJSON(r.Body, &payload))
					rec.mu.Lock()
					rec.requests = append(rec.requests, recordedWebhook{path: r.URL.Path, phase: payload.Phase})
					rec.mu.Unlock()
					if r.URL.Path == "/second" {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()

				canary := newHookTestCanary(hookType,
					flaggerv1.CanaryWebhook{Type: hookType, Name: "first", URL: server.URL + "/first", Timeout: "2s"},
					flaggerv1.CanaryWebhook{Type: hookType, Name: "second", URL: server.URL + "/second", Timeout: "2s"},
					flaggerv1.CanaryWebhook{Type: hookType, Name: "third", URL: server.URL + "/third", Timeout: "2s"},
				)
				ctrl, _, _ := newHookTestController()
				contract := mustWebhookContract(hookType)

				require.False(t, runHooks(t, ctrl, contract, &fakeHookController{}, canary, canary.Status.Phase))

				var paths []string
				for _, req := range rec.recorded() {
					paths = append(paths, req.path)
				}
				assert.Equal(t, []string{"/first", "/second"}, paths, "the third hook must not be called")
			})
		}
	})

	t.Run("post-rollout runs every hook", func(t *testing.T) {
		var mu sync.Mutex
		var paths []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths = append(paths, r.URL.Path)
			mu.Unlock()
			if r.URL.Path == "/second" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		canary := newHookTestCanary(flaggerv1.PostRolloutHook,
			flaggerv1.CanaryWebhook{Type: flaggerv1.PostRolloutHook, Name: "first", URL: server.URL + "/first", Timeout: "2s"},
			flaggerv1.CanaryWebhook{Type: flaggerv1.PostRolloutHook, Name: "second", URL: server.URL + "/second", Timeout: "2s"},
			flaggerv1.CanaryWebhook{Type: flaggerv1.PostRolloutHook, Name: "third", URL: server.URL + "/third", Timeout: "2s"},
		)
		ctrl, _, _ := newHookTestController()

		require.False(t, ctrl.runPostRolloutHooks(canary, flaggerv1.CanaryPhaseSucceeded))
		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, []string{"/first", "/second", "/third"}, paths)
	})

	t.Run("rollback stops at the first request", func(t *testing.T) {
		var mu sync.Mutex
		var paths []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths = append(paths, r.URL.Path)
			mu.Unlock()
			if r.URL.Path == "/first" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		canary := newHookTestCanary(flaggerv1.RollbackHook,
			flaggerv1.CanaryWebhook{Type: flaggerv1.RollbackHook, Name: "first", URL: server.URL + "/first", Timeout: "2s"},
			flaggerv1.CanaryWebhook{Type: flaggerv1.RollbackHook, Name: "second", URL: server.URL + "/second", Timeout: "2s"},
		)
		ctrl, _, _ := newHookTestController()

		require.True(t, ctrl.runRollbackHooks(canary, canary.Status.Phase))
		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, []string{"/first"}, paths)
	})
}

func TestWebhookContractEmptyTypeIsRollout(t *testing.T) {
	rec := &webhookRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload flaggerv1.CanaryWebhookPayload
		require.NoError(t, decodeJSON(r.Body, &payload))
		rec.mu.Lock()
		rec.requests = append(rec.requests, recordedWebhook{path: r.URL.Path, phase: payload.Phase})
		rec.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	canary := newHookTestCanary(flaggerv1.RolloutHook,
		flaggerv1.CanaryWebhook{Type: "", Name: "untyped", URL: server.URL + "/untyped", Timeout: "2s"})
	ctrl, _, _ := newHookTestController()

	require.True(t, ctrl.runRolloutHooks(canary, &fakeHookController{}))
	assert.Equal(t, []flaggerv1.CanaryPhase{flaggerv1.CanaryPhaseProgressing}, rec.phases())
}

func TestWebhookContractEventHook(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	canary := newHookTestCanary(flaggerv1.EventHook,
		flaggerv1.CanaryWebhook{Type: flaggerv1.EventHook, Name: "one", URL: server.URL + "/one", Timeout: "2s"},
		flaggerv1.CanaryWebhook{Type: flaggerv1.EventHook, Name: "two", URL: server.URL + "/two", Timeout: "2s"},
	)
	ctrl, spy, _ := newHookTestController()

	ctrl.recordEventInfof(canary, "something happened")
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"/one", "/two"}, paths, "a failing event hook must not stop the next one")
	assert.Empty(t, spy.messages)
}

func TestWebhookContractRows(t *testing.T) {
	// Pin the exported columns so a table edit is always a deliberate change.
	type row struct {
		typ      flaggerv1.HookType
		multiple multipleHookPolicy
		blocks   bool
		counts   bool
		phase    flaggerv1.CanaryPhase
		alert    bool
		payload  flaggerv1.CanaryPhase
	}
	expected := []row{
		{flaggerv1.ConfirmRolloutHook, shortCircuitHooks, true, false, flaggerv1.CanaryPhaseWaiting, true, ""},
		{flaggerv1.PreRolloutHook, shortCircuitHooks, true, true, "", false, flaggerv1.CanaryPhaseProgressing},
		{flaggerv1.RolloutHook, shortCircuitHooks, true, true, "", false, flaggerv1.CanaryPhaseProgressing},
		{flaggerv1.ConfirmTrafficIncreaseHook, shortCircuitHooks, true, false, "", true, flaggerv1.CanaryPhaseProgressing},
		{flaggerv1.ConfirmPromotionHook, shortCircuitHooks, true, false, flaggerv1.CanaryPhaseWaitingPromotion, true, flaggerv1.CanaryPhaseProgressing},
		{flaggerv1.PostRolloutHook, runAllHooks, false, false, "", false, ""},
		{flaggerv1.RollbackHook, firstActionHooks, false, false, "", false, ""},
		{flaggerv1.EventHook, runAllHooks, false, false, "", false, ""},
	}
	require.Len(t, webhookContracts, len(expected))
	for i, want := range expected {
		got := webhookContracts[i]
		assert.Equal(t, want.typ, got.Type)
		assert.Equal(t, want.multiple, got.Multiple, "%s multiple policy", want.typ)
		assert.Equal(t, want.blocks, got.Blocks, "%s blocks", want.typ)
		assert.Equal(t, want.counts, got.CountsFailure, "%s counts", want.typ)
		assert.Equal(t, want.phase, got.FailurePhase, "%s failure phase", want.typ)
		assert.Equal(t, want.alert, got.FailureAlert, "%s alert", want.typ)
		assert.Equal(t, want.payload, got.PayloadPhase, "%s payload phase", want.typ)
	}
}

func TestWebhookContractDocumented(t *testing.T) {
	path := "../../docs/gitbook/usage/webhooks.md"
	doc, err := os.ReadFile(path)
	require.NoError(t, err)

	const begin = "<!-- BEGIN WEBHOOK CONTRACT -->"
	const end = "<!-- END WEBHOOK CONTRACT -->"
	content := string(doc)
	start := strings.Index(content, begin)
	require.Greater(t, start, -1, "%s must contain %s", path, begin)
	rest := content[start+len(begin):]
	stop := strings.Index(rest, end)
	require.Greater(t, stop, -1, "%s must contain %s", path, end)

	documented := strings.TrimSpace(rest[:stop])
	assert.Equal(t, strings.TrimSpace(renderWebhookContract()), documented,
		"the contract table in %s must match renderWebhookContract()", path)
}

func drainEvents(events chan string) []string {
	var got []string
	for {
		select {
		case ev := <-events:
			got = append(got, ev)
		case <-time.After(50 * time.Millisecond):
			return got
		}
	}
}
