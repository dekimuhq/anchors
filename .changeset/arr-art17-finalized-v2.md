---
"@dekimuhq/arr-profiles": patch
---

fix(gdpr.art17.erasure-finalized): the universal adapter now reads `kind` and
`tsa` from the signed v=2 envelope (`claim_type`, `tsa`) instead of the body.
A v=2 body carries neither, so every v=2 `ar.erasure.v1` receipt failed the
profile with `claim_type_mismatch`, TSA or not. A body that claims `kind`/`tsa`
is now ignored.
