---
"@dekimuhq/action": minor
---

`mintActionV2` now carries the `aiact_art12` overlay into the signed body (it was silently dropped), and refuses to sign a body that fails `verifyActionBody` or its profile's validator. A caller that relied on the mint signing an invalid body now gets a thrown error instead of a permanent invalid receipt.
