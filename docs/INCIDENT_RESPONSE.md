# Incident response

This runbook is a starting point for operators. It is not a substitute for
an incident commander, legal review, or customer notification obligations.

1. **Detect:** preserve request IDs, verification failures, authentication
   spikes, anchor failures, and unusual export volume.
2. **Triage:** identify affected tenants, time range, API keys, checkpoints,
   anchors, and whether payload confidentiality or integrity is affected.
3. **Contain:** revoke affected keys, disable exports or ingestion if needed,
   isolate the signer, and preserve the original database and logs read-only.
4. **Recover:** rotate keys through the configured KMS/signer, restore into a
   clean environment, re-verify chains against external checkpoints, and
   document any unverifiable interval.
5. **Notify:** follow the contract, DPA, and applicable breach-notification
   timelines. Do not describe a chain as tamper-proof; report exact evidence.

For a suspected integrity failure, never rewrite the affected chain in place.
Export the evidence, compare it with signed checkpoints and customer-held
anchors, and start a new chain after containment.
