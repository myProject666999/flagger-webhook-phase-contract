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
	"fmt"
	"sort"
	"strings"
	"time"

	flaggerv1 "github.com/fluxcd/flagger/pkg/apis/flagger/v1beta1"
)

// defaultWebhookTimeout is the request timeout used when a webhook does not
// declare one. It is the only place the default is applied: both
// CallWebhook and CallEventWebhook go through webhookTimeout.
const defaultWebhookTimeout = 10 * time.Second

// multipleHookPolicy describes what happens when more than one webhook of the
// same type is declared.
type multipleHookPolicy string

const (
	// shortCircuitHooks stops at the first failing webhook, the remaining
	// webhooks of the same type are not called.
	shortCircuitHooks multipleHookPolicy = "short-circuit"
	// runAllHooks calls every webhook of the type even if one fails.
	runAllHooks multipleHookPolicy = "run-all"
	// firstActionHooks stops at the first webhook that answers with a 2xx,
	// failing webhooks do not prevent the remaining ones from being called.
	firstActionHooks multipleHookPolicy = "first-action"
)

// webhookContract is the authoritative description of a webhook type. Every
// behavioural decision that is not specific to a call site is taken from this
// table, and renderWebhookContract turns the exported columns into the
// user-facing table in docs/gitbook/usage/webhooks.md.
type webhookContract struct {
	// Type is the hook type this row describes.
	Type flaggerv1.HookType
	// When describes when Flagger executes the hooks of this type.
	When string
	// Multiple is the policy for several hooks of the same type.
	Multiple multipleHookPolicy
	// Blocks reports whether a failure stops the current analysis cycle.
	Blocks bool
	// CountsFailure reports whether a failure increments status.failedChecks.
	CountsFailure bool
	// FailurePhase is the phase a failure moves the canary to. Empty means the
	// failure does not change the phase.
	FailurePhase flaggerv1.CanaryPhase
	// FailureAlert reports whether a failure emits a notifier alert.
	FailureAlert bool
	// PayloadPhase is the phase sent in the request payload. Empty means it is
	// described by PayloadPhaseNote instead (call-site dependent).
	PayloadPhase flaggerv1.CanaryPhase
	// PayloadPhaseNote documents a call-site dependent payload phase.
	PayloadPhaseNote string

	// checkLabel is used in "<label> check <name> passed" and
	// "<label> hook <name> failed" events.
	checkLabel string
	// haltLabel is used in the "Halt <canary> advancement ..." events of
	// gating hooks.
	haltLabel string
	// alertMessage is the notifier message emitted on failure.
	alertMessage string
	// emitPassedEvent controls the informational event on success. Rollout
	// hooks stay silent on success to keep the existing event stream.
	emitPassedEvent bool
	// repeatFailureIterationsReset resets the iteration counter when a gate
	// fails while the canary already waits at that gate. Only confirm-promotion
	// does this.
	repeatFailureIterationsReset bool
	// countFailureMetric records failed invocations in the webhook failure
	// metric. Used by the non-blocking post-rollout hooks.
	countFailureMetric bool
	// inverted is true when a 2xx response requests an action (rollback)
	// instead of granting one.
	inverted bool
}

// webhookContracts is the single source of truth for webhook behaviour. Keep
// the rows in the order in which the types appear in the rollout lifecycle.
var webhookContracts = []webhookContract{
	{
		Type:             flaggerv1.ConfirmRolloutHook,
		When:             "Once per cycle after a target change is detected, before the canary is scaled up; retried every cycle until approved",
		Multiple:         shortCircuitHooks,
		Blocks:           true,
		CountsFailure:    false,
		FailurePhase:     flaggerv1.CanaryPhaseWaiting,
		FailureAlert:     true,
		PayloadPhaseNote: "current status phase",
		checkLabel:       "Confirm-rollout",
		haltLabel:        "waiting for approval",
		alertMessage:     "Canary is waiting for approval.",
		emitPassedEvent:  true,
	},
	{
		Type:            flaggerv1.PreRolloutHook,
		When:            "Once at the start of an analysis, before traffic is routed to the canary (weight 0, no iterations)",
		Multiple:        shortCircuitHooks,
		Blocks:          true,
		CountsFailure:   true,
		PayloadPhase:    flaggerv1.CanaryPhaseProgressing,
		checkLabel:      "Pre-rollout",
		haltLabel:       "pre-rollout check",
		emitPassedEvent: true,
	},
	{
		Type:            flaggerv1.RolloutHook,
		When:            "Once per analysis cycle before the metric checks; a webhook with an empty type is treated as rollout",
		Multiple:        shortCircuitHooks,
		Blocks:          true,
		CountsFailure:   true,
		PayloadPhase:    flaggerv1.CanaryPhaseProgressing,
		checkLabel:      "Rollout",
		haltLabel:       "external check",
		emitPassedEvent: false,
	},
	{
		Type:            flaggerv1.ConfirmTrafficIncreaseHook,
		When:            "Before each canary weight increase, except in Promoting, WaitingPromotion and Finalising and when traffic is mirrored",
		Multiple:        shortCircuitHooks,
		Blocks:          true,
		CountsFailure:   false,
		FailureAlert:    true,
		PayloadPhase:    flaggerv1.CanaryPhaseProgressing,
		checkLabel:      "Confirm-traffic-increase",
		haltLabel:       "waiting for traffic increase approval",
		alertMessage:    "Canary traffic increase is waiting for approval.",
		emitPassedEvent: true,
	},
	{
		Type:                         flaggerv1.ConfirmPromotionHook,
		When:                         "At the promotion gate, when the canary weight or iteration count reaches the maximum, before the spec is copied to the primary",
		Multiple:                     shortCircuitHooks,
		Blocks:                       true,
		CountsFailure:                false,
		FailurePhase:                 flaggerv1.CanaryPhaseWaitingPromotion,
		FailureAlert:                 true,
		PayloadPhase:                 flaggerv1.CanaryPhaseProgressing,
		checkLabel:                   "Confirm-promotion",
		haltLabel:                    "waiting for promotion approval",
		alertMessage:                 "Canary promotion is waiting for approval.",
		emitPassedEvent:              true,
		repeatFailureIterationsReset: true,
	},
	{
		Type:               flaggerv1.PostRolloutHook,
		When:               "Once when the analysis finishes: on success, on skipped analysis, on rollback and when promotion fails",
		Multiple:           runAllHooks,
		Blocks:             false,
		CountsFailure:      false,
		PayloadPhaseNote:   "Succeeded on success or skipped analysis, Failed on rollback or failed promotion",
		checkLabel:         "Post-rollout",
		haltLabel:          "post-rollout check",
		emitPassedEvent:    true,
		countFailureMetric: true,
	},
	{
		Type:             flaggerv1.RollbackHook,
		When:             "Once per cycle while the canary is Progressing, Waiting or WaitingPromotion; a 2xx response requests a rollback",
		Multiple:         firstActionHooks,
		Blocks:           false,
		CountsFailure:    false,
		PayloadPhaseNote: "current status phase",
		checkLabel:       "Rollback",
		inverted:         true,
	},
	{
		Type:             flaggerv1.EventHook,
		When:             "On every Kubernetes event Flagger emits, including events produced by the other hooks",
		Multiple:         runAllHooks,
		Blocks:           false,
		CountsFailure:    false,
		PayloadPhaseNote: "current status phase",
		checkLabel:       "Event",
	},
}

// canonicalHookType maps aliases onto the type that owns the behaviour. The
// empty type is an alias for the rollout hook.
func canonicalHookType(t flaggerv1.HookType) flaggerv1.HookType {
	if t == "" {
		return flaggerv1.RolloutHook
	}
	return t
}

// webhookContractFor returns the contract row for a hook type.
func webhookContractFor(t flaggerv1.HookType) (webhookContract, bool) {
	t = canonicalHookType(t)
	for _, row := range webhookContracts {
		if row.Type == t {
			return row, true
		}
	}
	return webhookContract{}, false
}

// mustWebhookContract returns the contract row for a known type and panics
// otherwise. It is only used with constants defined in this package.
func mustWebhookContract(t flaggerv1.HookType) webhookContract {
	row, ok := webhookContractFor(t)
	if !ok {
		panic(fmt.Sprintf("no webhook contract for hook type %q", t))
	}
	return row
}

// isValidHookType reports whether t is a known hook type. The empty type is
// valid because it is the documented alias for the rollout hook.
func isValidHookType(t flaggerv1.HookType) bool {
	_, ok := webhookContractFor(t)
	return ok
}

// validHookTypes returns the accepted hook type names sorted, with the empty
// alias first.
func validHookTypes() []string {
	names := []string{fmt.Sprintf("%q", "")}
	var rest []string
	for _, row := range webhookContracts {
		rest = append(rest, fmt.Sprintf("%q", row.Type))
	}
	sort.Strings(rest)
	return append(names, rest...)
}

// validateWebhookConfig rejects webhook types and timeouts that the controller
// would otherwise silently ignore or only discover when a hook is called.
func validateWebhookConfig(canary *flaggerv1.Canary) error {
	analysis := canary.GetAnalysis()
	if analysis == nil {
		return nil
	}
	for _, webhook := range analysis.Webhooks {
		if !isValidHookType(webhook.Type) {
			return fmt.Errorf("webhook %q has unknown type %q, valid types are: %s",
				webhook.Name, webhook.Type, strings.Join(validHookTypes(), ", "))
		}
		if _, err := webhookTimeout(webhook); err != nil {
			return err
		}
	}
	return nil
}

// webhookTimeout resolves the request timeout of a webhook, applying the
// default only when no timeout is configured.
func webhookTimeout(w flaggerv1.CanaryWebhook) (time.Duration, error) {
	if w.Timeout == "" {
		return defaultWebhookTimeout, nil
	}
	timeout, err := time.ParseDuration(w.Timeout)
	if err != nil {
		return 0, fmt.Errorf("webhook %q has invalid timeout %q: %v", w.Name, w.Timeout, err)
	}
	if timeout <= 0 {
		return 0, fmt.Errorf("webhook %q has invalid timeout %q: must be a positive duration", w.Name, w.Timeout)
	}
	return timeout, nil
}

// renderWebhookContract returns the contract as a Markdown table. The document
// in docs/gitbook/usage/webhooks.md embeds this text verbatim; the test
// TestWebhookContractDocumented keeps the two in sync.
func renderWebhookContract() string {
	var b strings.Builder
	b.WriteString("| Type | When | Multiple hooks of the same type | Failure blocks | Failure counts towards failed checks | Failure changes phase | Failure alerts | Payload phase |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, row := range webhookContracts {
		failurePhase := "no"
		if row.FailurePhase != "" {
			failurePhase = fmt.Sprintf("%s (first failure only)", row.FailurePhase)
		}
		alert := "no"
		if row.FailureAlert {
			alert = "yes (`muteAlert` mutes it)"
		}
		payloadPhase := string(row.PayloadPhase)
		if payloadPhase == "" {
			payloadPhase = row.PayloadPhaseNote
		}
		b.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s | %s | %s | %s | %s |\n",
			row.Type,
			row.When,
			row.Multiple,
			yesNo(row.Blocks),
			yesNo(row.CountsFailure),
			failurePhase,
			alert,
			payloadPhase,
		))
	}
	return b.String()
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
