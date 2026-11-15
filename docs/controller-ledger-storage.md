# Controller ledger storage

The controller keeps one authoritative live commit record, `business.json`.
Owned format 2 separates its encrypted mutable ledger from the immutable encrypted
handover checkpoint in `business.archive-<ciphertext-sha256>.json`. The archive
contains the original migration history; it is never a second current
configuration or traffic writer.
Import/export packages and unadopted staging checkpoints remain self-contained.

The ledger's authenticated encryption binds its snapshot ID and the exact SHA256
of the archive ciphertext. Startup authenticates both files and checks the existing
storage key, adoption intent, source identity and captured ownership. Missing,
changed or mismatched files fail closed. Each write retains the current-file,
archive, storage-key and adoption-identity fences; the in-memory parsed source
header is reused only after its source-byte fingerprint matches.

Each accepted accounting change still atomically writes and synchronizes the
live ledger before acknowledgement. Reporting intervals, counter watermarks,
out-of-order/repeated-sample handling, resets, quotas and node identity checks are
unchanged. This is not periodic batching. Immutable source history is neither
removed nor compacted to obtain the reduction.

## Forward migration and recovery

On the first owned-state load, the controller validates the existing format-1
checkpoint and retains those exact encrypted bytes as the archive. It synchronizes
that private file before atomically publishing the smaller format-2 ledger.
The storage migration does not issue node revisions or reset accounting. An
interrupted archive-first migration keeps the original files and fails closed for
explicit recovery. A format-1 ledger in a directory already containing an archive
is likewise rejected: the controller cannot distinguish an interrupted first
migration from replay of a previously committed old ledger. It never reconstructs
state from an older pending import. Use a matching complete recovery point in a
new directory; do not delete files to force the migration to retry.

The migration changes the storage format. An older controller cannot open format
2: restoring an older program requires its matching pre-migration recovery state,
not simply replacing the executable. Do not run legacy offline tools that accept
only a self-contained format-1 checkpoint against the new live ledger. The updated
`purge-retired-history` tool authenticates either format through the controller
reader and preserves all live fields. Offline history redaction is a separate,
explicit maintenance operation, not a normal ledger update. It writes an immutable
replacement archive first, atomically commits the bound format-2 ledger last,
then removes only authenticated, same-ownership superseded archive generations.
An interruption before commit leaves the old pair readable; after commit, a retry
cleans unused generations without rewriting accounting. Unknown archives remain
for review. The caller must stop both writers and hold the directory lease.

Archive evidence, even without the live ledger or adoption intent, blocks
transport-only startup, staging, adoption replay and fresh initialization.
Restore a matching complete recovery point instead of recreating the ledger.

The built-in encrypted controller backup includes both linked files and validates
their relationship before recovery. Backups use the logical `business.archive.json`
slot; restore derives the physical archive filename from the authenticated digest.
The storage key and installation identity credentials remain separately managed,
as before. A manual stopped-state recovery
must likewise retain the matching ledger, archive, adoption record, node state,
storage key and installation credentials. Do not copy a changing directory and
call it a consistent backup.

## Local comparison

Issue #188 uses the same opt-in `TestOwnedLedgerResourceComparison` workload on
both the original and optimized code: synthetic 15 MiB retained history, 74
counter records and one authenticated observation per second. It measures process
CPU time and Linux `/proc/self/io` deltas after setup/migration, then verifies all
counter deltas and the complete business material after reopening. It does not
contact production or introduce a production collection-interval change.

Set `GLIVELA_LEDGER_COMPARE=1` only for this explicitly requested local comparison;
normal CI skips the timed workload. The standard migration/integrity/backup tests
run normally. Synthetic measurements show this path's relative cost, not the
absolute CPU a production controller will use with different traffic or hardware.
