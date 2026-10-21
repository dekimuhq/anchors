/**
 * Pass-through `BodyValidator<AirBody>` adapter for the family manifest.
 *
 * AIR's hand-rolled `verifyV2` does NOT validate the body at envelope level;
 * structural body checks live in `verify-single.ts` (`verifyAirBody`) and are
 * invoked separately by callers that hold a body in hand. The factory's
 * `verifyReceipt` pipeline DOES include a body-schema step. To preserve
 * byte-equal output under the Phase 4B factory migration, the manifest hands
 * the factory a pass-through validator that always accepts. Full structural
 * validation stays in `verifyAirBody`, where callers already depend on it.
 *
 * Mirrors `anr-verifier/src/body-validator.ts` verbatim — every closure-set
 * member adopting the factory faithful-wrap pattern follows the same shape.
 */

import { passthroughBodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import type { AirBody } from "./types.ts";

export const airBodyValidator = passthroughBodyValidator<AirBody>();
