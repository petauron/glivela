# Native init adapters

Glivela's native worker supports systemd and OpenRC through its local installation
inventory. This adapter changes service management, not controller identity,
authorization, configuration ownership or desired-state communication.

A version 1 inventory denotes the existing systemd installation. Version 2 with
`initSystem: openrc` identifies executor-owned `/etc/init.d` scripts. The root-owned
inventory and script digests are checked before service actions. Per-service
OpenRC conf.d overrides are rejected. An administrator cannot select a different
init backend through a remote bootstrap or desired-state message.

OpenRC's supervised child PID is combined with kernel boot identity and process
start ticks. Worker executable, arguments, UID, capabilities, sockets and runtime
configuration retain their existing checks. The installer reconstructs volatile
credentials/configuration before the process starts and waits for the actual
application to exec. Starting the supervisor alone does not prove readiness.

The application distribution must contain static or native musl executables for
Alpine. Native installer and signed Catalog SDK publication are coordinated
separately; no systemctl emulation, arbitrary host-command channel or dependency
on Vastora business APIs is introduced. Existing controller data is not migrated
by this change.

The opt-in fixture in `tools/alpine-acceptance` uses independent synthetic
identities, an isolated resolver and the project's pinned Caddy HTTPS target.
It is not part of a release. The fixture does not represent production subscription business acceptance.
