---
"@dekimuhq/anchors-envelope": patch
---

Security hardening. Status lists: a signed list must now carry the `id` of the URL the pointer named (`list_mismatch`/`list_id_mismatch`), and a rolled-back list is rejected when the supplied cache has seen a newer verified `validFrom` (`list_rollback`) or when the new optional `minListValidFrom` / `maxListAgeSec` bounds fail (`list_too_old`); same checks for suspension lists. New additive `status_blocking` result field on the family verify pipeline (true when revoked or status unverifiable; `signature_valid` is unchanged). Issuer PQC mandate: a `sig2` verified only against the receipt's self-supplied `sig2_key` no longer counts toward `verifyIssuerPqc`; bind it via `resolveSig2Key`. `iss_key` / `sig2_key` algorithm-prefix binding now requires the `:` separator.
