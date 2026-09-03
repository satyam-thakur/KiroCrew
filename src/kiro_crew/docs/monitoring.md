# Monitoring pull requests and changing work

Kiro Crew can watch a public GitHub pull request until it is review-ready while
keeping model use proportional to real changes. Cheap status probes run on a
schedule; the owning conversation wakes only when new evidence needs action.

## Start a pull-request monitor

In a dashboard, Slack, or Discord conversation, ask Kiro Crew to babysit or
monitor the full pull-request URL. The supported first release watches public
`github.com` pull requests for the `review_ready` objective.

The default monitor is finite:

| Limit | Default |
|---|---:|
| Probe interval | 5 minutes |
| Runtime | 4 hours |
| Completed agent turns | 8 |
| Reported aggregate input and output tokens | 250,000 |
| Consecutive provider errors | 3 |

The tool reply means application is pending in the owning session. It does not
prove the monitor is active. End that turn so the session can apply the request;
the operator can then confirm it in the dashboard. The agent cannot inspect
after ending the same turn. At the start of a later user turn or monitor wake,
it calls `monitor_inspect` before acting or reporting. The retained state shows
its target, objective, next probe, bounds, latest classification, usage, and
final outcome.

The token cap applies only to usage the model provider reports. Inspection's
`token_usage_known` field says whether all completed-turn usage was available.
The runtime and completed-agent-turn caps remain hard fallbacks when it was not.

## What spends a model turn

The status probe and comparison happen before the conversation is invoked:

| Observation | Agent turn |
|---|---:|
| No material change | 0 |
| Checks still pending | 0 |
| Provider retry | 0 |
| Review-ready success or terminal blocker | 0 |
| New actionable fingerprint | At most 1 |

An actionable wake contains a compact summary. The agent can then fetch the
specific logs, comments, or diff needed for the change instead of replaying the
whole polling history. A restart cannot wake twice for the same accepted
fingerprint.

Terminal success does not wake the conversation or spend another model turn. A
dashboard notification reports structured success, blockers, exhausted budgets,
and unavailable owning sessions. When a conversational final report must be
generated even if no action is needed, ask for a finite legacy loop instead.

## Inspect, update, stop, and restart

Inspect on a later turn after creating or editing a monitor, and before reporting
its result. Cadence, positive budgets, and compact wake instructions can change
without discarding the comparison baseline. Changing the target or objective
starts a new baseline and is refused while an action is in flight.

Stopping is durable: the dashboard and agent inspection keep a `user_stop`
outcome rather than deleting the evidence. Success, provider/authentication
blocks, exhausted budgets, unavailable sessions, and missing completion evidence
also retain a specific terminal reason. Terminal records are read-only. Use the
dashboard Restart action or ask the agent to start a new explicit watch.

Monitoring does not grant extra tool authority. An action turn uses the normal
governance and approval policy for its conversation.

## Unsupported targets use the costly legacy loop

Tickets, deployments, other forges, and custom objectives are not yet structured
monitor kinds. Kiro Crew can use a legacy same-session goal loop for them, but
every delivered check is a full agent turn. It extends the conversation context
and spends model and tool tokens even when the target did not change.

Keep a legacy loop finite with a positive interval, cycle cap, and runtime
budget. Its acknowledgement is also only an arm request; verify the active goal
loop in the dashboard. Stop deliberately when the objective is met, the target
is terminal, or a person must decide. Approval can be requested, rejected, or
time out on an unattended channel turn; monitoring is never a blanket approval
grant.
