# Production readiness checklist

- [ ] Replace the local API key with scoped, hashed, expiring keys and rotation.
- [ ] Use PostgreSQL with FORCE RLS, separate migration/runtime roles, and
  append-only event permissions.
- [ ] Put signing keys in KMS/HSM or a separate signer; never in the app or DB.
- [ ] Configure two independent anchors and a customer-held transparency feed.
- [ ] Enable TLS, HSTS, strict CORS, CSP, rate limits, quotas, and WAF controls.
- [ ] Complete Argon2id/OIDC/MFA production identity integration.
- [ ] Add RBAC enrollment, auditor access expiry, and access logging.
- [ ] Enable envelope encryption, retention/legal hold, encrypted backups, and
  restore/deletion drills.
- [ ] Run bandit, semgrep, pip-audit, npm audit, gitleaks, Trivy, ZAP, and an
  independent penetration test in CI or release gates.
- [ ] Complete incident-response, DPA, subprocessors, SOC 2 readiness, and
  customer security review.

The local MVP intentionally does not claim these controls are complete.
