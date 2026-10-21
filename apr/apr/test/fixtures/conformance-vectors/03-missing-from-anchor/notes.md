# 03-missing-from-anchor

Claim signature is valid in isolation (key `test-claim-2026`). But the published daily root for the anchor date covers a different id set (`01J0TEST00000000000000A099`). Conforming verifier MUST rebuild the root from the published id set, observe that the claim id is NOT in it, and return `tampered` / `missing-from-anchor`. Per spec §8 step 4 this is a hard failure.
