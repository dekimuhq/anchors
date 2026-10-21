# 04-rotated-kid

Claim was signed by the older key `test-claim-2025`. The catalog still carries that key alongside the newer `test-claim-2026`. Receipts signed before rotation MUST keep verifying after rotation, as long as the old kid is retained in the catalog. Conforming verifier MUST return `verified`.
