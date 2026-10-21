# @dekimuhq/anchors

Meta-package for the Anchored Receipts protocol family. One install, surgical subpath imports, namespaced index.

**Version:** 0.8.8 (covers all 8 shipped families + envelope + resolver).

## Install

```bash
npm install @dekimuhq/anchors
```

Requires Node ≥24.6. Published under the `@dekimuhq` npm scope.

Pulls in all 8 shipped family triples (APR, ACR, ARR, ALR, ANR, ASR, ABR, AIR),
`@dekimuhq/anchors-envelope`, and `@dekimuhq/did-web-resolver`.

## Usage

### Namespaced index

```ts
import { apr, acr, acrProfiles, arr, arrProfiles } from "@dekimuhq/anchors";

const provenance = apr.mint({ /* ... */ });
const consent = acr.mintConsent({ /* ... */ });
const consentOk = acrProfiles.validateGdprArt7(consent);
const erasure = arr.mintErasure({ /* ... */ });
const erasureOk = arrProfiles.validateGdprArt17(erasure);
```

### Surgical subpath imports (tree-shakeable)

```ts
import { mint } from "@dekimuhq/anchors/apr";
import { mintConsent, verifyReceiptSignature } from "@dekimuhq/anchors/acr";
import { validateGdprArt7 } from "@dekimuhq/anchors/acrProfiles";
import { mintErasure, verifySingleReceipt } from "@dekimuhq/anchors/arr";
import { validateGdprArt17 } from "@dekimuhq/anchors/arrProfiles";
```

## Exports

| Subpath | Re-exports from |
|---|---|
| `@dekimuhq/anchors` | namespaced index — `apr`, `acr`, `acrProfiles`, `arr`, `arrProfiles` |
| `@dekimuhq/anchors/apr` | `@dekimuhq/apr` ^0.7.1 (verify `.` + issuer-kit `./issue`) |
| `@dekimuhq/anchors/acr` | `@dekimuhq/acr` ^0.7.0 (verify `.` + issuer-kit `./issue`) |
| `@dekimuhq/anchors/acrProfiles` | `@dekimuhq/acr-profiles` ^0.7.0 |
| `@dekimuhq/anchors/arr` | `@dekimuhq/arr` ^0.9.0 (verify `.` + issuer-kit `./issue`) |
| `@dekimuhq/anchors/arrProfiles` | `@dekimuhq/arr-profiles` ^0.8.2 |
| `@dekimuhq/anchors/alr` | `@dekimuhq/alr` ^0.5.0 (verify `.` + issuer-kit `./issue`) + profiles |
| `@dekimuhq/anchors/anr` | `@dekimuhq/anr` ^0.7.0 (verify `.` + issuer-kit `./issue`) + profiles |
| `@dekimuhq/anchors/asr` | `@dekimuhq/asr` ^0.6.0 (verify `.` + issuer-kit `./issue`) + profiles |
| `@dekimuhq/anchors/abr` | `@dekimuhq/abr` ^0.6.0 (verify `.` + issuer-kit `./issue`) + profiles |
| `@dekimuhq/anchors/air` | `@dekimuhq/air` ^0.7.0 (verify `.` + issuer-kit `./issue`) + profiles |
| `@dekimuhq/anchors/envelope` | `@dekimuhq/anchors-envelope` ^0.12.0 — sign/verify, canonicalize, types |
| `@dekimuhq/anchors/tsa` | RFC 3161 timestamps + EUTL trust-anchor catalog |
| `@dekimuhq/anchors/status` | W3C Status List 2021 fetch + verify + cache |

## Specs

- APR: https://github.com/dekimuhq/anchors-spec/blob/main/apr/v1.md
- ACR: https://github.com/dekimuhq/anchors-spec/tree/main/acr
- ARR: https://github.com/dekimuhq/anchors-spec/tree/main/arr
- ALR: https://github.com/dekimuhq/anchors-spec/tree/main/alr

Cross-family invariants: [`../meta/FAMILY-CONSISTENCY.md`](FAMILY-CONSISTENCY.md)

## License

Apache-2.0.
