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

## Stage the original account model

After exporting, the same **offline-only** tool can translate the reviewed
account/credential/route/usage tables into Glivela's existing import model and
stage it in a stopped controller's private directory:

```sh
legacy-export stage-accounts \
  -archive /private/transfer/legacy.sealed \
  -snapshot migration-example \
  -transfer-key /private/transfer/key \
  -storage-key /private/controller/storage.key \
  -state-directory /private/controller/state
```

This uses the source application identity as the entry identity, not a new
registration. Original account/credential/grant IDs, protocol UUIDs, subscription
tokens, Hysteria authentication, desired/applied revisions, disabled flags,
reset timestamps, quota baselines, observed totals and directional/raw counters
are copied and cross-validated. Missing usage watermarks, changed credentials,
unknown references or wrong storage classes abort. A legitimately absent line
sample remains unobserved; it is not fabricated from the raw counters.

The existing controller directory lease excludes a running process. Its
`accounts.pending.json` is encrypted with an independent storage key, not the
temporary transfer key. Identical retries do not rewrite it; changed counters
under the same snapshot cannot replace the verified checkpoint. This operation
does not activate accounts, publish subscriptions or accept route health.
Keep the complete encrypted export and original backup: account staging alone
does not import endpoints, landing policy or history, and is not permission to
delete or stop any old resources.

This is a **business-table extraction checkpoint, not a complete handover**.
Platform object references, selected landing settings, diagnostic/task history
outside these tables, and final usage observations still require explicit
transfer/reconciliation before activation. No API consumes this raw archive as
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
exact quotas above 2^53, reset schedules and directional samples. This proves
offline account staging only, not an active subscription or a complete cutover.
