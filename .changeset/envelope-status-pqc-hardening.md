---
"@dekimuhq/anchors-envelope": patch
---

Security hardening. Status lists: a signed list must now carry the `id` of the URL the pointer named (`list_mismatch`/`list_id_mismatch`), and a rolled-back list is rejected when the supplied cache has seen a newer verified `validFrom` (`list_rollback`) or when the new optional `minListValidFrom` / `maxListAgeSec` bounds fail (`list_too_old`); same checks for suspension lists. New additive `status_blocking` result field on the family verify pipeline (true when revoked or status unverifiable; `signature_valid` is unchanged). Issuer PQC mandate: a `sig2` verified only against the receipt's self-supplied `sig2_key` no longer counts toward `verifyIssuerPqc`; bind it via `resolveSig2Key`. `iss_key` / `sig2_key` algorithm-prefix binding now requires the `:` separator.

Follow-up: rollback defence now survives an invalid-signature fetch (the cache entry holding the verified high-water mark is restored), rejects clearing a known-revoked bit at an equal `validFrom` on revocation lists, and documents the publisher contract (sign `validFrom` = signing time, strictly increasing). `status_blocking` is now an allowlist (unknown states block).

The verified high-water mark / known set is now written only after the list's statusPurpose matches and its `encodedList` decodes (an undecodable signed list can no longer disable the equal-`validFrom` rollback check; it fails closed). `maxListAgeSec` is documented as time-since-last-signing, not liveness.
