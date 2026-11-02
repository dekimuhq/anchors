---
"@dekimuhq/anchors-envelope": patch
"@dekimuhq/aar": patch
"@dekimuhq/abr": patch
"@dekimuhq/air": patch
"@dekimuhq/alr": patch
"@dekimuhq/anr": patch
---

security(tsa): a MANDATORY TSA mandate now fails closed on any `tsa_state`
other than `"tsa_verified"`.

Previously a MANDATORY mandate hard-failed only when the `tsa` block was
absent. `tsa` sits outside the envelope signature (it is zeroed out of the
signing input), so anyone could attach a junk block to a genuine receipt —
garbage bytes (`tsa_malformed`), a token from an unrecognised TSA, an imprint
mismatch, drift beyond tolerance — and the receipt kept `signature_valid: true`,
bypassing the mandate entirely.

**Behaviour change (MANDATORY only):** a present-but-unverified `tsa` block now
returns `signature_valid: false` with `reason: "tsa_required"`. `tsa_state`
keeps the real TSA reason (e.g. `"tsa_malformed"`) so callers can see why; the
absent case is unchanged. Covers the shared pipeline's profile-keyed mandate
(`acr.esig.accept@qes`, `arr.gdpr.art17.erasure-finalized`,
`notice.aiact.art50_transparency`) and the body-keyed family post-steps (AAR
issuance+qts, ABR `breach.detected`, ANR art50; AIR/ALR scaffolding). The
family post-step now leaves an earlier, more specific failure reason intact.
RECOMMENDED and OPTIONAL behaviour is unchanged.
