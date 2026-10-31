# Retained landing handover

This is a per-node operation, not fleet rollout or data cleanup. Preserve DNS,
the selected exit, source allowlists, identities, configuration, subscription
addresses and the existing entry-side accounting authority. Do not import or
reset accounting merely to replace the landing transport.

1. Back up the controller, Agent and exact old landing using
   `backup-legacy-landing`. Prepare the signed native landing package and its
   private mTLS identity. Keep the original proxy serving until preflight passes.
2. Persistently stop/mask the old Agent while switching. Use the existing
   `switch-legacy-landing` command and its verified checkpoint. Never manually
   rewrite the cutover journal, weaken firewall checks or discard old files.
3. Enroll the exact candidate revision and complete source inventory in Glivela.
   Run the existing authenticated entry-side route checks, using one snapshot
   identity. Local process readiness alone is insufficient.
4. Stop only the Glivela node daemon to acquire its directory lock; keep Xray
   running. Run `glivela complete-legacy-landing -config <private-bootstrap>
   -snapshot-id <verified-snapshot>`. It checks the current worker, old writer
   fence and retained backup, then queries the controller through the node's
   own mTLS identity. Missing, partial, stale or failed route evidence is refused.
   An explicitly [temporarily suspended](temporary-availability.md) source is
   retained and recorded as deferred, not passed. All remaining active sources
   must pass; an entirely suspended inventory cannot complete acceptance.
5. Restart the Glivela node daemon. With Agent still masked, use the supporting
   Vastora release's `agent retire-landing-execution --native-state <owned-state>`.
   This retains the old journal and recovery material, fencing only old landing
   recovery, mutation and observation. Unmask/start Agent only after this succeeds.
6. Verify private node reports, public subscription identities and actual double
   hops from each required entry, plus monotonic accounting. Only then proceed to
   the next selected landing. Do not remove old services, accounts or backups.

The accepted journal binds the original candidate, checkpoint, route snapshot
and acceptance time. Subsequent native revisions are allowed only while the old
writer remains fenced. Failed acceptance leaves `awaiting-routes` intact; failed
switches retain the existing explicit recovery path rather than declaring success.

No controller-wide subscription cutover, fallback exit or Agent-wide disablement
is part of the final state. If any prerequisite cannot be established, stop on
that node instead of treating an unverified switch as complete.
