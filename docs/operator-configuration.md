# Retained operator configuration

These files belong in the existing private Glivela state directory. They contain
operator choices, not built-in vendor aliases or permission inferred from a node.
Keep them private (0600), back them up for the specific change, and retain them
across ordinary program updates. The installer does not need a new capability.

## Issued subscription names

Before replacing a program which transformed names, capture the actual issued
VLESS display name for each retained entry through its authenticated existing
subscription. Stage `subscription-names.json` in the controller state directory
before the managed upgrade, owned/readable by the controller's configured UID:

```json
{"version":1,"names":{"entry-example":"Example entrance"}}
```

Use entry IDs matched by the complete existing connection identity, not by guessed
names or address alone. Include the full issued label, including its existing
region prefix. Helpers and route names then derive from the same explicit label;
client chains retain their separately saved names. URLs, keys and UUIDs do not
belong in this file. The program validates entries, unique labels and private
file permissions before binding subscriptions; malformed input stops startup.
There is no vendor-name inference, alternative endpoint or direct fallback.

The controller's encrypted consistent backups include this optional file, and
reject a file changed behind the running controller. Restore only to an offline
new private destination. Configuration recovery never restores an old ledger.
Ordinary absence uses the retained service's own display name.

## Independently managed host firewall

A native node with a separately managed input DROP guard may explicitly identify
that existing table in `host-firewall.json` in its node state directory:

```json
{"version":1,"table":"operator_guard"}
```

Only a root-owned private regular file is accepted. Family `inet`, chain `input`,
input hook and DROP policy stay fixed. Glivela-owned tables cannot be selected.
Without this file the documented table is `host_guard`. An unknown additional
DROP policy is still refused; the program never searches for a permissive table.
This setting does not create, rename or flush a table, persist a port exception,
change production proxy grants or relax the exact peer-source/time-limit checks.
It applies only to the existing temporary speed-test exception and its recovery.
Retain the configured table and this file while recovery resources still exist.

## Shared client landing cutover

Upgrade the controller and one selected landing through the existing signed
catalog before applying shared listeners. Back up only the required private
configuration/state and current source rules; reuse a verified pre-change recovery
point on retries. Preserve server forwarding on 1080, DNS, exits and all account
and node identities. Keep subscriptions on their original origin/token.

The authenticated `client-chains` operation accepts `shareLanding:true`,
`accountId`, `egressId`, and current decimal-string `expectedRevision`. It selects
one independent client-only SS2022 AES-128-GCM key per single-account landing on
TCP 24000. Existing IPv4 and explicitly authorized IPv6 sources retain their exact
addresses. Keys are not shared with server forwarding, management or another
landing/account. UDP remains disabled.

Preserve the old precise rules until acceptance. Add only the existing authorized
sources on TCP 24000 in the host/provider policies. Apply the transaction, wait
for its matching fresh landing receipt, refresh the real subscription and verify
each enabled chain through its original VLESS dependency and original exit before
continuing. Retained names/references and monotonic entry-side accounting must
match. Remove superseded client-port rules only after that landing passes.

On failure, stop the batch. `restoreLanding:true` with the same landing/account
and current revision restores the retained original per-chain configuration
through a forward revision. Never restore an older ledger, loosen source checks,
change the exit or fabricate health to continue.
