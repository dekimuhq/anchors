/**
 * Pass-through `BodyValidator<AnrBody>` adapter for the family manifest.
 *
 * ANR's hand-rolled `verifyV2` does NOT validate the body at envelope level;
 * structural body checks live in `verify-single.ts` (`verifyAnrBody`) and are
 * invoked separately by callers that hold a body in hand. The factory's
 * `verifyReceipt` pipeline DOES include a body-schema step. To preserve
 * byte-equal output under Phase 2 migration, the manifest hands the factory
 * a pass-through validator that always accepts. Full structural validation
 * stays in `verifyAnrBody`, where callers already depend on it.
 *
 * If a future migration wants the factory to enforce body shape at envelope
 * level, swap this for a wrapper around `verifyAnrBody` (see ALR for the
 * reference pattern). That is a breaking semver change — current verifyV2
 * callers do NOT expect malformed bodies to poison `signature_valid`.
 */

import { passthroughBodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import type { AnrBody } from "./types.ts";

export const anrBodyValidator = passthroughBodyValidator<AnrBody>();
