# Server-owned transport resources

Server forwarding owns its transport through `ImportMaterial.serverTransports`,
independently of client subscription publications. Each resource retains the
account, entry and landing identities, role certificates, exact peer, listener,
optional relay listener and expected exit. Inventory exposes resource identities
and route references, without transport keys.

The native wire format is unchanged. Existing listener and path IDs remain stable
physical identifiers; normal server authorization no longer resolves them through
client-chain records or shared client credential maps.

## One-way ownership migration

Loading owned business state with transport schema version 0 captures only exact,
already-enrolled server bindings. It verifies the existing client material,
certificates, listeners, peer, source and expected exit before saving version 1.
Active server paths require their exact listeners to remain enrolled. For inactive
paths, an absent socket is captured from the authenticated saved policy; a
same-ID listener with different fields is always rejected. Capturing inactive
ownership never reactivates a listener.
Native server grants that already use the landing main transport also capture
the existing landing certificate into managed server authority. This requires
the original account authority and exact entry certificate, source, peer,
transport and landing management-address bindings; it creates no listener or
permission. Client publication cleanup cannot remove this server authority.
Unknown schemas, ambiguous ownership or mismatched bindings fail closed. The
controller also requires projection of the migrated state to leave the complete
node configuration unchanged. Migration does not delete client records or alter
traffic history, accounts, credentials, ports or running services.

After ownership is established, the existing client-chain deletion operation may
remove a disabled publication while its independent server resource stays active.
Applied, fresh entry/landing/relay receipts and an exact owned binding are required.
If the server listener has already been withdrawn, the normal fresh withdrawal
checks apply instead. No enabled client publication is implicitly removed.

## Resource lifecycle

The authenticated administrator endpoint `POST /v1/admin/server-transports`
accepts a resource, the account's `expectedRevision` string, and optional `delete`.
It claims only exact listeners already applied to authenticated nodes. It does not
create sockets, generate credentials, widen source authorization or expose keys.
Physical resource fields are immutable; a name change preserves the resource ID.

Deleting ownership requires all associated grants to be deleted, all peers and
listeners to be withdrawn, and fresh applied receipts from every involved node.
Client publication deletion and server-resource deletion are separate operations.
Before projecting any node configuration, both two-hop and three-hop peers must
match owned identities and transport parameters. An enabled grant cannot lose its
peer through enrollment; mismatches reject the operation before state is saved.

Reactivating an existing managed server grant checks its owned configuration and
the landing/relay current mTLS identities without requiring a stopped socket to
already exist. Projection restores only the owned listener. Runtime startup and
subscription publication still require applied listeners, fresh receipts and the
existing actual path checks; the reactivation check cannot mark a route ready.
Port allocation reserves owned landing and relay sockets even after their old
client publication is deleted. Node retirement requires releasing server
ownership first.

## Deployment boundary

This changes the encrypted controller business-file structure. Before a separately
authorized rollout, retain one consistent matching recovery point with the
controller state, encryption key and identity/configuration materials. An older
controller must not open the new state; rollback requires restoring the matching
state and program together. Worker protocol changes or fleet-wide upgrades are
not required by this ownership change.

Source preparation alone does not perform migration, delete publications or prove
live proxy health. Migration, identity/deletion regression verification and real
existing-route checks must complete before accepting a production cleanup.
