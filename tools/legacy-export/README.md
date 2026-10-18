# One-time offline legacy export

This isolated Go module is the **only** Glivela module allowed to depend on
`modernc.org/sqlite v1.60.1`. It is not built by the native runtime distribution
and neither controller nor node imports it. CI tests this module separately and
checks that the runtime dependency graph contains no `modernc.org` package.

Build from this directory with `GOWORK=off go build -o /private/tool/location`.
Use only an operator-prepared, private, standalone **frozen backup**, not the
running Center database. The reviewed input is Center schema 113. Other schema
versions fail closed; this tool never migrates or repairs its input. WAL, SHM
and rollback journal sidecars are refused. SQLite is opened read-only and
immutable; source bytes are hashed before and after extraction. This cannot
prove that a running old writer is fenced: that is a separate cutover gate.

All input/output paths must be absolute with safe, non-symlink parent
directories. Inputs must be private regular files. Both keys are raw 32-byte
files; the temporary transfer key must differ from the original Center key.
Never put key contents in command arguments or environment variables.

```sh
legacy-export \
  -database /private/backup/center.db \
  -source-key /private/backup/center.key \
  -transfer-key /private/transfer/key \
  -snapshot migration-example \
  -output /private/transfer/legacy.sealed
```

The new output is exclusively created with mode 0600, fsynced along with its
directory, and never overwrites an earlier export. The AES-256-GCM envelope
authenticates the snapshot identity. Its version-1 payload contains the source
schema/hash, every column/row of the sixteen reviewed business tables, and only
the decrypted secrets referenced by those rows. Original secret IDs and AAD
ownership are retained; the Center master key and unrelated secrets are not
exported. Integer counters use exact decimal strings, with distinct text,
blob and null storage classes. Missing tables, newly encountered business
tables/secret-reference columns, foreign-key violations and authentication
failures abort without a successful output. Console output contains no records
or underlying database errors.

## Stage one complete private checkpoint

After exporting, the same **offline-only** tool can translate the reviewed
account/credential/route/usage and endpoint tables into Glivela's import model.
It retains the complete exported source records/history in the same encrypted
checkpoint, in a stopped controller's private directory:

```sh
legacy-export stage \
  -archive /private/transfer/legacy.sealed \
  -snapshot migration-example \
  -transfer-key /private/transfer/key \
  -storage-key /private/controller/storage.key \
  -state-directory /private/controller/state
```

The checkpoint now includes the related node/application/service/publication
reference graph and the original landing selection (revision, active/retiring
IDs, regions and suffixes). Original node/application/service/publication IDs,
names, advertised domains/SNI and DNS resource references are copied, not
re-created. Unconfigured Glivela instances remain unconfigured. Missing or
unrelated application references fail closed; no new node identity is invented.
Only related proxy services/publications and required nodes are read. Agent
authentication hashes, platform login state, component capability inventories
and shared Cloudflare/provider tokens are deliberately excluded. Resource IDs
and old statuses do not authorize DNS/resource adoption or prove live health.
Optional unknown network observations remain unknown (including JSON null),
not a guessed address, an empty measurement or a new successful check.

This uses the source application identity as the entry identity, not a new
registration. Original account/credential/grant IDs, protocol UUIDs, subscription
tokens, Hysteria authentication, desired/applied revisions, disabled flags,
reset timestamps, quota baselines, observed totals and directional/raw counters
are copied and cross-validated. Missing usage watermarks, changed credentials,
unknown references or wrong storage classes abort. A legitimately absent line
sample remains unobserved; it is not fabricated from the raw counters.

Endpoint preflight now verifies the complete REALITY/Hysteria configuration,
original secret ownership, certificates/expiry, protocol switches, service and
entry references, quota/reset fields and historical observations before staging
accounts. A configured but disabled protocol retains its keys and certificates.
The reviewed schema-113 constraint requires at least one configured protocol
flag even for retired endpoints; retirement is preserved through its recorded
status, not by clearing both protocol flags. Historical healthy/applied values
never count as new runtime or TLS acceptance. These complete endpoint records
are retained together with the accounts and immutable exported source, not in
separate files that could be committed only halfway.

The existing controller directory lease excludes a running process. Its
`business.pending.json` is encrypted with an independent storage key, not the
temporary transfer key. Identical retries do not rewrite it; changed counters
under the same snapshot cannot replace the verified checkpoint. This operation
does not activate accounts, publish subscriptions or accept route health.
Endpoint changes, retained-history changes and source hash changes also prevent
a retry from overwriting the existing checkpoint, even if the account-plan hash
is unchanged. The transfer authentication binds the embedded source snapshot ID.
The replaced account-only command/envelope/reader is removed, not a fallback.
Keep the complete encrypted export and original backup. This one atomic pending
checkpoint is not the final write-authority transfer, and is not permission to
delete or stop old resources. Actual resource ownership, shared integrations,
settings/history outside the exported scope and final counters still require
explicit reconciliation before activation.

This is a **business-data staging checkpoint, not a complete handover**.
Diagnostic/task history outside these tables, final usage observations and
actual resource ownership still require explicit transfer/reconciliation before
activation. No API consumes this raw archive as
live authority. Exporting does not start/stop services, change subscriptions,
fence the old writer, clear migration alarms or delete old resources.

Tests use synthetic records and verify identities, counters above 2^53, blob/
null distinctions, scoped secret recovery, wrong key/snapshot, tamper refusal,
unchanged source bytes, no overwrite, sidecar/symlink refusal and schema drift.
Do not publish real backup archives, keys or migration data in PRs/CI artifacts.

The 2026-10-19 anonymous integration run generated a complete schema-113 backup
using the retained Vastora source's shared-endpoint/route fixtures, then ran the
actual export and staging commands. Independent decryption/reopen compared the
entire normalized model and verified two accounts, three credentials, one route,
one nonempty route-health history record, exact quotas above 2^53, reset schedules
and directional samples. Independent read-only SQL joins also compared the
original node/application/service/publication binding and display/domain data
against the reopened checkpoint. Scope tests include unrelated applications,
Agent authentication hashes and a shared provider-token sentinel; none may be
exported. Truncated or tampered checkpoints expose no partial
material and cannot be silently overwritten on retry. This proves
offline business staging only, not an active subscription or a complete cutover.
