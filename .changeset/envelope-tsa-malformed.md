---
"@dekimuhq/anchors-envelope": patch
---

fix(tsa): a malformed `tsa` block is reported as `tsa_state: "tsa_malformed"`
instead of throwing out of `verifyTsa` / family `verifyReceipt`.

`tsa` sits outside the envelope signature, so anyone could attach bytes that do
not parse as a TimeStampResp (or a non-string `tsr`) to a genuine receipt and
make verification throw rather than return `signature_valid: true` with a failed
TSA. `verifyTsa` now honours its documented never-throws contract. `TsaReason`
gains the additive member `"tsa_malformed"`.
