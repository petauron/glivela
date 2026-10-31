# Fresh controller initialization (MVP)


A fresh installation has no legacy writer to stop or database to adopt. Use
`initialize-business` offline against the installed controller's private bootstrap:

```sh
glivela initialize-business -config /etc/glivela/controller.json \
  -topology /etc/glivela/fresh-topology.json \
  -storage-key /etc/glivela/business.key
```

The storage key is an independently generated, private 32-byte file. Never reuse
production credentials. The private topology JSON contains `endpoints` and
`references` using the existing typed endpoint/reference models. Initial endpoints
must be pending at revision 1 with no applied observation, usage, retirement or
migration runtime binding. No accounts, protocol credentials or traffic history
are imported. Create accounts through the existing management API/UI afterward.

Stop the controller first so its directory lease can be acquired. Run maintenance
with the state volume's service UID, or preserve that UID when privileged
maintenance creates files. The controller container runs as UID/GID 65532; private
files must remain readable only by their intended service/operator. Bootstrap
activation also requires write access to its containing directory.

Initialization refuses existing nodes, pending business, owned business, adoption
intent or handover acknowledgement. It creates an encrypted native-origin ledger
and a durable creation intent; it does not invent a stopped writer or legacy
schema. A failed/incomplete transaction is retained for explicit recovery. Never
remove an intent to force initialization or regenerate a storage key after state
has been created. Repeating initialization must not reset accounts or counters.

Continue with `activate-controller` (the storage key, private subscription listen
address and an actually published HTTPS origin), then `enroll-nodes` with separately
issued node certificates and reviewed plans. Enrollment authorizes exact peer
identities before the first account route; it does not grant a client access.
REALITY target verification, authenticated private-peer checks, firewall source
restrictions, runtime receipts and subscription health gates remain mandatory.

A development binary override is not a signed release. Do not present an installed
alpha package version as proof that locally overridden code has been published.
Real acceptance requires a generated subscription and a client HTTPS request.

The `owned` inventory state confirms ledger ownership only. Node runtime readiness
and route verification remain separate live checks. Account applied revisions
retained from migration are not fabricated as runtime acceptance receipts.
