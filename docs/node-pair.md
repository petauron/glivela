# Same-host entry and landing

Use the `node-pair` bootstrap for a fresh installation that needs both roles.
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
