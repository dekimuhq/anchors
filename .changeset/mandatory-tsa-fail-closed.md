---
"@dekimuhq/anchors-envelope": patch
"@dekimuhq/aar": patch
"@dekimuhq/abr": patch
"@dekimuhq/air": patch
"@dekimuhq/alr": patch
"@dekimuhq/anr": patch
---

security(tsa): a MANDATORY TSA mandate now fails closed on any `tsa_state`
other than `"tsa_verified"`; the TSA reference time defaults to the signed
`iat`.

Previously a MANDATORY mandate hard-failed only when the `tsa` block was
absent. `tsa` sits outside the envelope signature (it is zeroed out of the
signing input), so anyone could attach a junk block to a genuine receipt —
garbage bytes (`tsa_malformed`), a token from an unrecognised TSA, an imprint
mismatch, drift beyond tolerance — and the receipt kept `signature_valid: true`,
bypassing the mandate entirely.

**Behaviour change (MANDATORY):** a present-but-unverified `tsa` block now
returns `signature_valid: false` with the new reason `"tsa_unverified"`
("timestamp not confirmed" — e.g. a verifier that lacks or does not trust the
TSA anchor), distinct from `"tsa_required"` (no timestamp at all). `tsa_state`
keeps the real TSA reason (e.g. `"tsa_malformed"`) so callers can see why; the
absent case is unchanged (`reason: "tsa_required"`). Enforced by the shared
pipeline's profile-keyed mandate (`acr.esig.accept@qes`,
`arr.gdpr.art17.erasure-finalized`, `notice.aiact.art50_transparency`) and by
the body-keyed post-steps in the AAR / ABR / ANR top-level `verifyReceipt`
(issuance+qts, `breach.detected`, art50; AIR/ALR scaffolding). The post-step
now leaves an earlier, more specific failure reason intact. Note: the
body-keyed post-steps run only in each package's top-level `verifyReceipt`;
callers of `aarFamily` / `abrFamily` / `anrFamily.verifyReceipt` directly (and
the CLI's family dispatch) do not run them — a pre-existing gap tracked
separately.

**Behaviour change (all levels): default TSA reference time is the signed
`iat`, not the verifier's clock.** `tsaReferenceTime` still overrides. The
token's `genTime` must lie within `tsaDriftToleranceSec` (default 300 s) of
`iat`, and the trust anchor must be valid at `iat` (long-term validation).
Without this, fail-closed MANDATORY would have turned every genuine timestamped
receipt invalid ~5 minutes after mint for any caller that does not pin a
reference time. For RECOMMENDED / OPTIONAL this changes only advisory output:
fewer spurious `tsa_drift_exceeded` on old receipts, and a token stamped far
from its receipt's `iat` now reports `tsa_drift_exceeded`. `verifyTsa`'s expiry
and drift checks now fail closed on an unparseable reference time, anchor
`valid_until` or `genTime` (previously a NaN comparison passed).

Downstream verifiers must supply trust anchors for the TSA that issued a
token: the bundled default is FreeTSA only, so eIDAS QTSP anchors are needed
for qualified profiles (`acr.esig.accept@qes`, `notice.aiact.art50_transparency`).
RECOMMENDED and OPTIONAL signature behaviour is unchanged.
