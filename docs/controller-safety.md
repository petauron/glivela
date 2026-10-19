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
