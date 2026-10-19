# Controller safety ownership

Glivela owns target guards, controller-data recovery and route health. Source
code and a green CI gate do not authorize removing an installed legacy writer
or claiming a production route has passed.

## Existing REALITY targets

Owned import retains the original hostname/history and the previously reviewed
`TargetIP`. Entry projection uses that fixed IP on port 443, preserving keys,
SNI, short IDs and subscription identities. It does not resolve a new target,
choose a different CDN/WAF or treat historical route health as fresh evidence.
The MVP does not introduce new target selection or a new provider database.

Before validating/starting a changed native entry, Glivela connects directly to
the pinned public IP with every retained SNI. TLS 1.3, X25519, h2 and ordinary
certificate-chain/hostname verification are mandatory. Private/special-purpose
IPs and hostname-only executable fallback targets fail closed. A failed check
does not stop an existing runtime. Resuming the unchanged, already-owned process
does not periodically restart it or reselect its target.

## Hourly controller-data snapshots

The controller starts its own backup loop, independent of Vastora heartbeat.
After business adoption it captures `business.json`, `business.adoption.json`
and `nodes.json` under the existing Store lock, verifies the on-disk business
and node state, and encrypts the snapshot with standard AES-256-GCM using the
independently held business key. Each successful write requires byte readback
and authenticated decryption. Errors are reported without exposing data/paths.

Two private `controller-backup-0.gcm` / `controller-backup-1.gcm` slots rotate
hourly. An existing slot must authenticate before it can be replaced; an
unknown/corrupt file is not deleted. Other migration/upgrade backups are never
touched. The storage key and installation TLS credentials remain separately
protected and must be retained; these data snapshots do not replace the generic
installation/volume backup made before an upgrade. Backups never grant health.

An enrolled management certificate can request an immediate snapshot with the
same-origin JSON `POST /v1/admin/backup`. Nodes cannot invoke this operation.

To recover, use the installed Glivela executable locally:

```sh
glivela restore-controller-backup \
  -backup /private/recovery/controller-backup-0.gcm \
  -storage-key /private/keys/business.key \
  -destination /private/recovery/restored-controller
```

The destination must not exist, and its parent must be private. The command
authenticates the snapshot, creates only the three fixed data files, then opens
the restored Store and checks its adopted business/key binding. It does not
overwrite the active directory, change bootstrap, restart a service, claim
current route health or automatically downgrade data. Partial destinations stay
private for explicit inspection. After operator review, activate the restored
directory only with the controller stopped and its configuration/identities
retained. The running controller waits for its backup loop before releasing its
directory lease during shutdown.

## Health is not process startup

Native entry activation installs/verifies its owned output policy and per-peer
gates. `NodeRunner` sends independently observed configuration/process/firewall
state through the direct mTLS exchange. The entry's independent `RouteRunner`
tests the authorized landing with HTTPS certificate validation and checks the
observed public exit. Controller acceptance checks revision/digest, full source
inventory and freshness. A failed peer closes only its own gate; no ordinary
probe failure restarts the shared worker. Subscriptions require current runtime
and route evidence, not imported healthy flags.

Before retiring Vastora's old safety triggers, verify these Glivela paths and
their real installed ownership. Preserve the shared Docker HAProxy and all
unrelated routes, generic Agent management and private recovery evidence.

## Names and billing cycles

Keep imported node/service names verbatim; do not recreate the platform's old
automatic name normalization. Imported services retain their IANA site timezone.
Endpoint monthly boundaries advance in that timezone, including DST and short
months, rather than using a timestamp's fixed offset as the timezone. The
standard Go timezone database is embedded for the scratch controller image.
An endpoint with a reset day but no source timezone is rejected; recapture the
frozen source with the matching offline exporter, rather than guessing UTC.

Authenticated node exchange advances overdue endpoint/account cycles from the
recorded boundary. Repeated polls do not reset again, and raw core watermarks
survive the reset. No online node means no remote configuration can change;
the first authenticated poll catches up before sending the next policy.
Account expiry disables authentication through the same desired projection,
not through a platform task or restarting unrelated peers.

## Platform API retirement map

The independent controller listener requires an enrolled administrator mTLS
certificate. The public subscription listener only accepts retained tokens.
Neither endpoint proxies a platform cookie or a Vastora application command.

| Former platform responsibility | Application-owned replacement |
| --- | --- |
| Account/client plans, quotas and resets | `/v1/admin/accounts`, `/v1/admin/account-plan`, `/v1/admin/account-reset`; authenticated exchange advances retained cycles |
| Subscription generation/disclosure | `/v1/admin/account-subscription` and the separate `SubscriptionHandler`, retaining the original origin/token path |
| Route grants and revocation | `/v1/admin/routes`, with enrolled peer identity checks and fresh acceptance |
| Entry/landing configuration and protocol inventory | Typed `/v1/admin/entries`, `/v1/admin/landings` and offline `enroll-nodes`; existing ownership/configuration is retained, not discovered from a platform task |
| REALITY target hardening | Fixed reviewed IP plus `verifyEntryRealityTargets` before native activation; no automatic new target selection |
| Link verification and recovery status | Direct `NodeRunner`/`RouteRunner`, `/v1/admin/route-checks` and `/v1/admin/route-acceptance`; startup is never route proof |
| Controller backup/restoration | `/v1/admin/backup`, hourly snapshots and `restore-controller-backup` |
| Old Docker/3x-ui role changes and proxy removal commands | Explicit offline capture/adoption, stopped-source native handover, `retire-node`, then generic data-retaining uninstall |
| Automatic display-name normalization | Removed; retain source node and service names verbatim |

This is a migration of the retained inventory, not a second 3x-ui API or a new
automatic node/protocol discovery feature. Keep the old writer stopped before
final capture. Rebind the existing published subscription/backend to the new
private service only after data adoption, node enrollment and fresh real route
acceptance. Never remove/recreate publication identity, issue new tokens, mark
archived tasks successful or delete their source history to make a cutover pass.
