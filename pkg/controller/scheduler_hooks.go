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
	"fmt"

	flaggerv1 "github.com/fluxcd/flagger/pkg/apis/flagger/v1beta1"
	"github.com/fluxcd/flagger/pkg/canary"
	"github.com/fluxcd/flagger/pkg/metrics"
)

// hookFailure holds a failed webhook invocation.
type hookFailure struct {
	webhook flaggerv1.CanaryWebhook
	err     error
}

// hookOutcome is the result of running every webhook of one type according to
// the contract row for that type.
type hookOutcome struct {
	failed []hookFailure
	// actionRequested is set when an inverted hook (rollback) answered with a
	// 2xx response. It holds the webhook name.
	actionRequested string
}

// hasFailures reports whether at least one invocation failed.
func (o hookOutcome) hasFailures() bool {
	return len(o.failed) > 0
}

// firstFailure returns the first failed invocation, or false if none failed.
func (o hookOutcome) firstFailure() (hookFailure, bool) {
	if len(o.failed) == 0 {
		return hookFailure{}, false
	}
	return o.failed[0], true
}

// runHooksOfType invokes the webhooks of a type in declaration order, applying
// the multiple-hook policy from the contract. phase is the payload phase.
func (c *Controller) runHooksOfType(canary *flaggerv1.Canary, contract webhookContract, phase flaggerv1.CanaryPhase) hookOutcome {
	var outcome hookOutcome

	for _, webhook := range canary.GetAnalysis().Webhooks {
		if canonicalHookType(webhook.Type) != contract.Type {
			continue
		}

		err := CallWebhook(*canary, phase, webhook)
		if err != nil {
			outcome.failed = append(outcome.failed, hookFailure{webhook: webhook, err: err})
			// Only short-circuit stops at the first failure; run-all and
			// first-action keep going so a later hook can still act.
			if contract.Multiple != shortCircuitHooks {
				continue
			}
			break
		}

		if contract.emitPassedEvent {
			c.recordEventInfof(canary, "%s check %s passed", contract.checkLabel, webhook.Name)
		}
		// first-action stops at the first hook that requests the action.
		if contract.Multiple == firstActionHooks {
			outcome.actionRequested = webhook.Name
			break
		}
	}

	return outcome
}

// reportInvertedFailures emits the events for failed rollback hooks. An explicit
// non-2xx response is informational ("not signaling a rollback"); a transport
// failure such as a timeout or an unreachable host is a warning, so a broken
// rollback switch does not stay silent.
func (c *Controller) reportInvertedFailures(canary *flaggerv1.Canary, outcome hookOutcome) {
	for _, failure := range outcome.failed {
		if isWebhookStatusError(failure.err) {
			c.recordEventInfof(canary, "Rollback hook %s not signaling a rollback", failure.webhook.Name)
			continue
		}
		c.recordEventWarningf(canary, "Rollback hook %s is unreachable, treating it as not signaling a rollback: %v",
			failure.webhook.Name, failure.err)
	}
}

// applyFailureBudget records a failed hook invocation in the canary failure
// budget when the contract says so. The call sites invoke it for every blocking
// hook type, keeping the counting decision in the contract table.
func (c *Controller) applyFailureBudget(canary *flaggerv1.Canary, canaryController canary.Controller, contract webhookContract) {
	if !contract.CountsFailure || canaryController == nil {
		return
	}
	c.bumpFailedChecks(canary, canaryController)
}

// bumpFailedChecks increments status.failedChecks. It is shared by hook
// failures the contract counts and by failed metric checks.
func (c *Controller) bumpFailedChecks(canary *flaggerv1.Canary, canaryController canary.Controller) {
	if canaryController == nil {
		return
	}
	if err := canaryController.SetStatusFailedChecks(canary, canary.Status.FailedChecks+1); err != nil {
		c.recordEventWarningf(canary, "%v", err)
	}
}

// alertOnFailure emits the contract alert for a failed gating webhook, honouring
// the per-webhook muteAlert setting. muteAlert only has an effect on hook types
// whose contract sets FailureAlert.
func (c *Controller) alertOnFailure(canary *flaggerv1.Canary, contract webhookContract, webhook flaggerv1.CanaryWebhook) {
	if !contract.FailureAlert || webhook.MuteAlert {
		return
	}
	c.alert(canary, contract.alertMessage, false, flaggerv1.SeverityWarn)
}

// runPreRolloutHooks runs the pre-rollout gates. A failure blocks the cycle and
// is counted towards status.failedChecks as stated by the contract.
func (c *Controller) runPreRolloutHooks(canary *flaggerv1.Canary, canaryController canary.Controller) bool {
	contract := mustWebhookContract(flaggerv1.PreRolloutHook)
	outcome := c.runHooksOfType(canary, contract, contract.PayloadPhase)
	failure, ok := outcome.firstFailure()
	if !ok {
		return true
	}
	c.recordEventWarningf(canary, "Halt %s.%s advancement %s %s failed %v",
		canary.Name, canary.Namespace, contract.haltLabel, failure.webhook.Name, failure.err)
	c.applyFailureBudget(canary, canaryController, contract)
	return false
}

// runRolloutHooks runs the rollout webhooks, which are also the webhooks with an
// empty type. It runs before the metric checks of every analysis cycle; a
// failure blocks the cycle and is counted towards status.failedChecks.
func (c *Controller) runRolloutHooks(canary *flaggerv1.Canary, canaryController canary.Controller) bool {
	contract := mustWebhookContract(flaggerv1.RolloutHook)
	outcome := c.runHooksOfType(canary, contract, contract.PayloadPhase)
	failure, ok := outcome.firstFailure()
	if !ok {
		return true
	}
	c.recordEventWarningf(canary, "Halt %s.%s advancement %s %s failed %v",
		canary.Name, canary.Namespace, contract.haltLabel, failure.webhook.Name, failure.err)
	c.applyFailureBudget(canary, canaryController, contract)
	return false
}

func (c *Controller) runConfirmTrafficIncreaseHooks(canary *flaggerv1.Canary) bool {
	contract := mustWebhookContract(flaggerv1.ConfirmTrafficIncreaseHook)
	outcome := c.runHooksOfType(canary, contract, contract.PayloadPhase)
	failure, ok := outcome.firstFailure()
	if !ok {
		return true
	}
	c.recordEventWarningf(canary, "Halt %s.%s advancement %s %s",
		canary.Name, canary.Namespace, contract.haltLabel, failure.webhook.Name)
	c.alertOnFailure(canary, contract, failure.webhook)
	return false
}

func (c *Controller) runConfirmRolloutHooks(canary *flaggerv1.Canary, canaryController canary.Controller) bool {
	contract := mustWebhookContract(flaggerv1.ConfirmRolloutHook)
	// The payload carries the phase the canary is in before the gate runs.
	outcome := c.runHooksOfType(canary, contract, canary.Status.Phase)
	failure, ok := outcome.firstFailure()
	if !ok {
		return true
	}

	// Alert only on the transition into the waiting phase. While the canary
	// stays in Waiting the hook is retried every cycle without repeating the
	// event or the alert.
	if canary.Status.Phase != contract.FailurePhase {
		if err := canaryController.SetStatusPhase(canary, contract.FailurePhase); err != nil {
			c.logger.With("canary", fmt.Sprintf("%s.%s", canary.Name, canary.Namespace)).Errorf("%v", err)
		}
		c.recordEventWarningf(canary, "Halt %s.%s advancement %s %s",
			canary.Name, canary.Namespace, contract.haltLabel, failure.webhook.Name)
		c.alertOnFailure(canary, contract, failure.webhook)
	}
	return false
}

func (c *Controller) runConfirmPromotionHooks(canary *flaggerv1.Canary, canaryController canary.Controller) bool {
	contract := mustWebhookContract(flaggerv1.ConfirmPromotionHook)
	outcome := c.runHooksOfType(canary, contract, contract.PayloadPhase)
	failure, ok := outcome.firstFailure()
	if !ok {
		return true
	}

	if canary.Status.Phase != contract.FailurePhase {
		if err := canaryController.SetStatusPhase(canary, contract.FailurePhase); err != nil {
			c.logger.With("canary", fmt.Sprintf("%s.%s", canary.Name, canary.Namespace)).Errorf("%v", err)
		}
		c.recordEventWarningf(canary, "Halt %s.%s advancement %s %s",
			canary.Name, canary.Namespace, contract.haltLabel, failure.webhook.Name)
		c.alertOnFailure(canary, contract, failure.webhook)
	} else if contract.repeatFailureIterationsReset {
		// Keep the promotion gate paused without advancing the analysis.
		if err := canaryController.SetStatusIterations(canary, canary.GetAnalysis().Iterations-1); err != nil {
			c.recordEventWarningf(canary, "%v", err)
		}
	}
	return false
}

// runPostRolloutHooks runs the post-rollout notifications with the given payload
// phase. Failures never block the rollout: every hook is called, each failure is
// recorded as a warning event and counted in the webhook failure metric. The
// call sites ignore the returned bool, which only reports whether all hooks
// succeeded.
func (c *Controller) runPostRolloutHooks(canary *flaggerv1.Canary, phase flaggerv1.CanaryPhase) bool {
	contract := mustWebhookContract(flaggerv1.PostRolloutHook)
	outcome := c.runHooksOfType(canary, contract, phase)
	for _, failure := range outcome.failed {
		c.recordEventWarningf(canary, "Post-rollout hook %s failed %v", failure.webhook.Name, failure.err)
		if contract.countFailureMetric {
			c.recorder.IncWebhookFailures(metrics.WebhookMetricLabels{
				Name:      canary.Spec.TargetRef.Name,
				Namespace: canary.Namespace,
				HookType:  string(contract.Type),
			})
		}
	}
	return !outcome.hasFailures()
}

// runRollbackHooks evaluates the rollback hooks. A 2xx response signals that a
// rollback is requested; an explicit non-2xx response means no rollback. An
// unreachable webhook is also treated as no rollback, but a warning event is
// emitted so a broken rollback switch does not stay silent.
func (c *Controller) runRollbackHooks(canary *flaggerv1.Canary, phase flaggerv1.CanaryPhase) bool {
	contract := mustWebhookContract(flaggerv1.RollbackHook)
	outcome := c.runHooksOfType(canary, contract, phase)
	if contract.inverted {
		c.reportInvertedFailures(canary, outcome)
	}
	if outcome.actionRequested != "" {
		c.recordEventWarningf(canary, "Rollback check %s passed", outcome.actionRequested)
		return true
	}
	return false
}
