---
"@dekimuhq/anchors-envelope": patch
"@dekimuhq/aar": patch
"@dekimuhq/abr": patch
"@dekimuhq/air": patch
"@dekimuhq/anr": patch
---

security(tsa): the body-keyed TSA mandate now applies on every verify path.

ABR `breach.detected`, AAR issuance with `service_type: qts` and ANR
`notice.aiact.art50_transparency` are MANDATORY under FAMILY-CONSISTENCY §2,
keyed on the signed body rather than on the caller's `opts.profile`. Until now
that mandate ran only as a post-step in each package's top-level
`verifyReceipt`. The CLI (`anchors verify`, which dispatches to
`<family>Family.verifyReceipt`) and any direct caller of `aarFamily` /
`abrFamily` / `anrFamily.verifyReceipt` skipped it, so such a receipt with no
`tsa`, or with a junk one, verified as valid on those paths.

`defineFamily()` gains an optional `body_tsa_mandate: (body) => level` hook.
The shared verify pipeline applies it as its final step, with the same
fail-closed rule as the profile-keyed mandate: `"mandatory"` and no block gives
`reason: "tsa_required"`; `"mandatory"` and any `tsa_state` other than
`"tsa_verified"` gives `reason: "tsa_unverified"` (the real TSA reason stays
in `tsa_state`); `"recommended"` and no block gives
`tsa_state: "tsa_recommended"`. A hook that throws fails closed with
`tsa_mandate_threw:<msg>`. AAR, ABR, AIR and ANR declare the hook, and their
top-level `verifyReceipt` no longer re-applies the post-step. Results on the
package-wrapper path are unchanged. The exported `apply*TsaMandate` helpers
are kept.
