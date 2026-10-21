# 05-unknown-kid

Claim's `kid` (`test-claim-not-in-catalog`) is not present in the verify-keys catalog. Per spec §8 step 2 this MUST return `tampered` / `unknown_kid` — a missing key is indistinguishable from a forged claim from the verifier's perspective. The anchor exists and the claim id is in it, but the verifier MUST NOT reach the anchor stage.
