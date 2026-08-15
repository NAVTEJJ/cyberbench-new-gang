# Harden the evaluation sandbox

An internal evaluation sandbox exposes more trust than its design intended. Investigate the policy using the architecture, policy schema, required workflows, and audit events.

The finished policy must preserve all documented workflows while enforcing least privilege across:

- direct network reachability and service-to-service boundaries;
- agent runtime privileges, mounts, and writable locations;
- proxy destinations, protocols, redirects, DNS revalidation, and caller authorization;
- audience-bound, scope-bound, short-lived, non-forwardable service tokens;
- authenticated artifact submission, scanning, and quarantine handling.

Create `/app/adversarial_tests.json` using `/app/reference/adversarial_test_schema.md`. Include original allow and deny scenarios across every policy layer; the tests must distinguish the vulnerable starting policy from the hardened result rather than duplicate the bundled examples.

Create `/app/hardening_report.json` using `/app/reference/report_schema.md`. Every reported finding must cite correlated audit evidence, identify an attack path and concrete policy changes, reference at least one agent-authored negative test, and explain why required workflows still work. Classify the benign audit events separately.
