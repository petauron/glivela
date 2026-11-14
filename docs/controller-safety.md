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

## Runtime availability thresholds

The node monitor requires two consecutive successes to open a peer gate and
three consecutive network probe failures to close it. An intervening success
clears the failure streak. The first two failures retain a `degraded` receipt,
not a fabricated successful probe. Certificate, identity, configuration, exit
mismatch, unavailable security evidence and gate ownership errors fail closed
immediately. Direct-only transport verification is not relaxed.

Each renewal requires fresh security checks and is capped at 30 seconds; retained
business success is capped at 45 seconds. The third failure actively closes the
gate even before either deadline. Process loss cannot renew a kernel timeout.
The existing nftables set definition stays unchanged (15-second default); each
renewal supplies an explicit bounded element timeout. No service restart,
configuration deletion or cross-peer change is triggered by a normal failure.

Upgrade receipt consumers and the scoped node together: the new receipt carries
`securityCheckedAt`, failure/success streaks and the last actual business success.
Do not mark old or missing receipts healthy during a rolling update. Preserve
configuration, enrollment, subscription tokens and traffic watermarks.


## Explicit expired-host history removal

An operational retirement does not itself erase encrypted migration history or
old subscription snapshots. For an explicitly authorized no-history retirement,
the separately distributed offline tool provides `purge-retired-history`.

Stop both writers normally, verify the current shared recovery point, and use the
exact retired node IDs. The controller directory lock must be available and the
Center database must be standalone; the tool authenticates the owned checkpoint
and requires permanent landing revocation first. No remote host is contacted.

```sh
glivela-legacy-export purge-retired-history \
  --state-directory /private/controller-state \
  --center-directory /private/center-state \
  --node-ids '<exact-retired-id>,<exact-retired-id>' \
  --audit-file /private/task/token-fingerprints.json \
  --confirm-stopped-writers
```

The command removes target archive rows and unshared secret values, redacts their
references in mixed historical JSON and authenticated execution payloads, and
updates historical subscription checksums. Other owners' current credentials,
node policy, account ledger and subscription identities remain protected. Raw
integer values are decoded without floating-point conversion. A redacted archive
is marked and cannot be reused to transfer execution authority.

Center changes use one transaction with foreign keys retained. Any snapshot
update exception is restricted to the exact secret owner and its original freeze
guard is restored before commit. Center is committed first so an interrupted
operation can derive the same scope from the still-original controller archive.
The controller checkpoint is then authenticated, atomically replaced and synced.
The audit file contains one-way fingerprints only; it must not contain matched
secret values.

After successful normal startup and actual subscription acceptance, replace the
necessary shared recovery points with verified clean points. Enumerate and retire
superseded contaminated restore copies only after checking their task and process
references. Preserve other owners' data; never treat an encrypted backup as proof
that a target secret has been erased. Storage snapshots and recycle bins must be
included in the actual cleanup inventory when present.


## Pruning a retired entry

The administrator mTLS endpoint `POST /v1/admin/retire-returned-entry` accepts
`id`, `certificateId`, decimal-string `expectedRevision`, decimal-string
`expectedAvailabilityRevision`, `confirmHostReturned: true`, and `confirmation`
which must equal `id`. The existing returned-entry operation is the only cleanup
entry point; there is no separate permanent-delete API. It only removes an already-retired, offline entry with
an exact enrolled identity and revision, no pending transport/network/speed
operation, and no dependent client chain or owned server resource. Online entries
and mismatched identities are refused. Any change to a surviving runtime is also
refused; this operation never reconciles or reinstalls another node.

The encrypted business source is committed first. `prunedEntries` retains the
certificate revocation fence, endpoint/service/inbound identifiers and original
quota observations. Original account credentials, usage members, watermarks,
subscription identities, display-name evidence and source archive are unchanged.
Executable endpoint configuration (including SNI, listener and TLS configuration)
is removed, followed by its recoverable node projection. A restart or identical
retry completes an interrupted projection without restoring historical counters.
The retired identity and certificate cannot be enrolled again.

This is a forward-only business-state change. An older program must not open it;
program rollback requires a verified matching pre-change recovery point. Existing
automatic backups can supply that point after their contents and recovery scope
are verified; repeated diagnostic actions must not generate extra full snapshots.

DNS deletion is separate: check active listeners, publications, subscriptions and
other services first, and remove only an unused operator-owned record. Historical
source evidence is not another live configuration writer and is not rewritten to
remove old names. Third-party DNS records are never deleted by this operation.
