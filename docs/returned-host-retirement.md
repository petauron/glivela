# Permanently retire a returned entry

Use the existing authenticated management listener: `POST /v1/admin/retire-returned-entry` with `id`, `certificateId`, `expectedRevision`, `expectedAvailabilityRevision` (revision strings), `confirmation` equal to the exact runtime ID, and `confirmHostReturned: true`.

First stop publication of all dependent routes and client chains and set an indefinite maintenance suspension. The exact enrolled entry must have been offline for at least five minutes, have no active speed lease or pending transport transition, and not share a host with another runtime. The returned host is never contacted and no execution receipt is fabricated.

The encrypted business transaction removes this entry's endpoints, credentials and transports, preserves shared account identity and cumulative usage, and persists its revocation fence before projecting withdrawal to remaining nodes. Verify those nodes' actual receipts separately. Then confirm that the old certificate is rejected and real subscriptions contain no retired entries.

This is distinct from ordinary `retire-entry`, which preserves history. For permanent history removal, stop the relevant writers and use the published `glivela-legacy-export purge-retired-history` tool with exact retired runtime IDs. The revocation fence retains an authenticated source-host ID when different, so historical source records can be redacted without guessing by name or IP. Review explicit archive and backup targets; never delete shared backup files merely because a retired host occurs within them.

Use the Center's `purge-removed-entry-history` only after its normal permanent removal is complete and independent Glivela revocation is confirmed. No step claims the unreachable host itself was stopped or wiped. Keep the tracking issue open until live state and scoped historical copies have actually been verified.

For nodes added after the original migration, its archive cannot identify later dedicated secret values. An operator may pass `--redaction-words-file <private-JSON-array>` containing the exact target-only values captured before revocation. The root-only tool accepts a bounded private file and rejects values still used by a live credential. Keep this temporary input in protected volatile storage, never in a report or Git, and remove it immediately after verified cleanup. It is not a recovery backup.
