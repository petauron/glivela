# Public proxy egress (MVP)

Public destination ports are not classified as management services. Authorized
proxy users can reach public SSH, databases and remote desktops without an
extra public-SSH switch or a complete host-public-address inventory.

The existing post-resolution private/reserved-address guard, cloud metadata and
control-network isolation, account credentials, exact source grants, exit-family
limits and traffic quotas remain mandatory. Authorized resolver, managed local
TLS-origin and entry-to-landing exceptions retain their exact scope. A public
port permission does not authorize a private destination or a new UDP transport.
The existing REALITY UDP 443 policy is unchanged.

## Existing installations

Back up the controller's business/node state and node installation identity and
runtime journal through the normal application upgrade flow. Upgrade the native
node programs and controller from the signed application catalog. Do not clear
ledgers, re-enroll nodes or replace identities to apply this policy.

On controller startup, the one-time projection advances each retained desired
revision. Entry render versions retain the original UDP 443 bit; only the public
port blacklist is removed. Accounts, schedules, raw/forwarded counters and manual
availability are retained. An unfinished transport transition blocks migration
until it is resolved through its existing recovery flow.

Native workers install the new UID-scoped firewall table before removing the
complete, exactly verified old table. Old private snapshots remain immutable
recovery evidence; their historical renderer and firewall shape are retained
only for validation and owned cleanup. Changed or foreign old tables are never
adopted or deleted. Offline nodes remain pending; a green controller start is
not evidence that their runtime policy changed.

Verify actual public TCP 22 and another former blocked port, private-target
rejection, existing HTTPS/subscription access, and continuous account counters
before accepting deployment. Never restore a traffic ledger to revert a failed
program update; use the retained configuration with a new forward revision.

## Retained landing address changes

A removed public IP does not authorize re-enrollment or runtime journal edits.
Update the existing landing plan with an advancing revision. The native driver
validates every new local bind as usual, and removes only exact retained firewall
policies reconstructed on local interfaces with full ownership/rule readback.
The old IP need not remain assigned for cleanup or an authenticated pending retry;
unknown or changed rules are retained and the operation fails closed.

## Automatic address-family selection

An empty or `auto` native egress policy uses the bundled Xray's Happy Eyeballs
for TCP domain destinations. A failed address immediately advances to another
candidate; a pending attempt permits the next attempt after 250 ms. A successful
connection cancels the other attempts. Freedom's explicit business DNS and
post-resolution destination guards remain in force. This does not add UDP
fallback or change fixed landing routes, credentials or subscriptions.

`ipv4_only` and `ipv6_only` still force their selected family and block the
opposite family, including literal destinations. Use an explicit policy when
only that family is intended; automatic acceptance does not certify both families.

New entry artifacts use render version 7, retaining the existing UDP 443 and
public-port policy bits. Versions 0..3 remain unchanged for exact historical
snapshot validation. This change does not run a startup fleet migration: an
existing desired configuration retains its render version during account/quota,
route, listener and probe updates. Install compatible node programs before the
controller, then select the new format through an explicit managed entry update
with an advancing revision. Updating the controller alone does not enable this
policy on retained entries; never send format 7 to an older node program.
