# Same-host entry and landing

Use the `node-pair` bootstrap for an installation that needs both roles.
One Glivela manager supervises two existing single-role runtimes and two Xray
workers. Each role retains its own certificate, runtime directory, worker
UID/GID, service, firewall ownership, revision and applied receipt. A ready
entry never certifies the landing. Shared outbound permissions or a shared
worker user would break the landing's family/source restrictions and are
rejected before the paired manager starts either role.

The ordinary single-role `node` bootstrap and authenticated control protocols
are unchanged. Pairing does not weaken `Desired.Validate` to accept two plans,
merge source permissions, or introduce a second business writer.

The signed native installation declares one automatic root manager and two
manual workers. It supplies three separate state directories and a private
bootstrap with `mode: "node-pair"`, the manager's `installation`, `service`
and `directory`, and two nested `entryNode`/`landingNode` objects. Each child
uses the existing `mode: "node"` fields, the same installation/controller/CA,
its own `directory`, `certificate`, `key`, and an `xray` object with the exact
`role`, distinct installed worker `service`, and private `interface`.
Controller settings, recursive pair definitions, shared journals and shared
certificates or worker identities are refused. Existing single-role installs
are not silently converted or overwritten. Offline single-role handover
commands are not a migration path for a paired installation.

## Add the other role to an installed native node

`stage-node-pair` explicitly converts an existing installed native single-role
bootstrap without moving its journal, changing its driver binding or creating
another account/identity for that existing role. It works in either direction.
This is not a fresh dual-package reinstall or a native backend rebind.

First use a reviewed signed profile that retains the original `node` manager,
`xray` worker/user and `node-state`, and also declares the separate manual
`companion-xray` worker/user, `companion-state` and `pair-manager-state`.
An old profile without these resources is refused; the command never creates
services, users or state directories. An ordinary profile update still runs
the original single-role bootstrap and does not enable the dormant worker.
Staging an existing installation currently requires systemd. Existing OpenRC
single-role and fresh paired runtimes remain supported, but this maintenance
command refuses their conversion rather than guessing init-script ownership.

Prepare a private, root-owned complete paired candidate. Its existing child
must exactly equal the installed single-role bootstrap, including certificate,
controller, service, interface and state path. Its other child uses the same
installation/controller/CA and its own certificate/key, installed worker and
unused state directory. Supply the second role's persistent, root-owned key;
do not point it at a disappearing runtime credential copy. Enroll that role
through the existing authenticated controller procedure. Registration alone
does not authorize a source or create a public listener.

Stop only the owned manager through the normal service lifecycle before
staging; retain the existing worker and its original statistics generation.
The command requires exclusive state leases, a healthy committed original
runtime, no pending maintenance, a stopped installed second worker and distinct
trusted role certificates/keys and worker UID/GID. It does not recover a failed
source, reset a retired runtime or reinitialize an existing companion journal.

```sh
glivela stage-node-pair --config /private/installed/node.json --pair /private/pair.json
glivela stage-node-pair --config /private/installed/node.json --pair /private/pair.json --apply
```

Without `--apply`, only the preflight is performed. Applying saves one private
`single-role-bootstrap.json` recovery file in the paired manager directory,
reuses only an identical recovery file on retry, then atomically replaces the
installed bootstrap with a compare-before-write check. Neither runtime state,
controller business, certificates, source grants nor traffic counters is rewritten.
The command never restarts a service. Its saved status means **manager restart
required**, not that both roles or a client chain have passed acceptance.

Start the same manager normally, then confirm both independent controller
receipts. Configure the new role's explicitly authorized listeners and a
nonconflicting stats API port; keep the existing role's ports/configuration.
For client chains, retain the exact source addresses, second-hop family and
account credentials, then verify the exported dependencies and actual exit.
Do not advertise UDP merely because both roles run on one host.

Before the first paired start, failure recovery can restore the saved original
bootstrap while the manager is stopped. After the second role has accepted
state or traffic, do not silently revert to a single-role bootstrap: retain
both journals and settle/disable the second role through its normal workflow.
These instructions do not authorize a production conversion or restart.

An enrolled administrator can POST an `EndpointRegistration` to
`/v1/admin/endpoints` on the existing private mTLS API. It declares a fresh
endpoint and its node/application/service references, the entry certificate
fingerprint, explicit native exit family, and selected **existing** account
IDs. No imported receipt or consumed traffic is accepted. The controller
creates the entry's native credentials in those accounts, preserves the
subscription tokens/reset schedules/existing counters, and enrolls the
entry's initial desired state. The normal node protocol delivers credentials
only to that entry's authenticated identity. Retrying stable IDs reuses the
same credentials and cannot replace an endpoint or another node identity.

The landing uses its separate ordinary enrollment and explicit authorized
sources/listeners. Adding a landing does not grant other entries access or
create chain subscriptions. Select the intended entry and use the existing
client-chain operation to authorize and publish that route after actual
application. Both roles retain their own private isolation, account/traffic
policy, startup checks, and the existing UDP443 policy.

Business inventory includes each runtime's physical `hostId` where the owned
references establish it. The panel marks co-located roles and shows separate
states with a link between them. Configuration and traffic are still owned
by Glivela; Vastora only installs, updates and removes the signed application.
