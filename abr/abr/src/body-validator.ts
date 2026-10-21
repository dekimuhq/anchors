/**
 * Pass-through `BodyValidator<AbrBody>` adapter for the family manifest.
 *
 * ABR's hand-rolled `verifyV2` does NOT validate the body at envelope level;
 * structural body checks live in `verify-single.ts` (`verifyAbrBody`) and are
 * invoked separately by callers that hold a body in hand. The factory's
 * `verifyReceipt` pipeline DOES include a body-schema step. To preserve
 * byte-equal output under the Phase 4C factory migration, the manifest hands
 * the factory a pass-through validator that always accepts. Full structural
 * validation stays in `verifyAbrBody`, where callers already depend on it.
 *
 * Mirrors `anr-verifier/src/body-validator.ts` and
 * `air-verifier/src/body-validator.ts` verbatim — every closure-set member
 * adopting the factory faithful-wrap pattern follows the same shape.
 */

import { passthroughBodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import type { AbrBody } from "./types.ts";

export const abrBodyValidator = passthroughBodyValidator<AbrBody>();
