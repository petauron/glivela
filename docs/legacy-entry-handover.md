# Owned legacy entry to native runtime

The legacy checkpoint accepts the reviewed immutable source Xray 26.7.28 image,
as well as the current pinned worker image. The source pin does not select the
new runtime. All application labels, container ID/image, mounts, private config,
writer fencing and source/target proxy identity comparisons remain mandatory.
Unknown images and mutable tags are rejected.

Use the existing `backup-legacy-entry`, `stage-native-entry` and Vastora
`retire-legacy-execution` operations. Freeze and mask the old writer before
checkpointing or staging; keep it stopped until native acceptance and executor
retirement. Restore its original unit before the retirement command's loaded,
inactive-unit check, and start the Agent only after successful retirement.
Keep the exact old container/config and necessary private recovery materials
until actual HTTPS and subscription acceptance have passed.

## Retired verifier-only references

The authenticated administrator `POST /v1/admin/entries` operation accepts an
optional `previousVerifierCertificateId`. Supply the independently recorded
previous certificate SHA256 only when handing an owned legacy entry over to its
native direct-only runtime. Ordinary enrollment does not infer or rotate it.

The operation requires an owned, non-retired endpoint with its legacy writer
retired, no enrolled node with that entry/previous-certificate identity, and all
server-side/client-chain grants for that entry already deleted and disabled.
Every retained verifier reference must match the expected certificate and the
original private address. Only those references and their old entry-specific
checks are retired; other checks, landing configurations, identities, receipts,
account data and historical traffic are preserved. Any projection that would
change another node's runtime is refused. New entry readiness still requires its
own normal application and real client acceptance.

Deleted route grants remain in the business ledger, but are not reintroduced by
later route edits and do not require obsolete transports for runtime acceptance.
Disabled historical credentials remain disabled; they never become direct users.
This recovery does not authorize a source/container change, host reinstallation,
other-node deployment or bypass of an unsuccessful checkpoint.
