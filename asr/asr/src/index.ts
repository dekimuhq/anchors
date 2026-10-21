/**
 * @dekimuhq/asr — public surface (verify; mint lives at `./issue`).
 *
 * Phase 3 greenfield via `defineFamily()` — the package re-exports the
 * frozen `asrFamily` manifest and the supporting types. Mint + verify are
 * pre-bound on the manifest (`asrFamily.mintV2` / `asrFamily.verifyReceipt`).
 */

export { asrFamily, ASR_PROFILES } from "./family.ts";
export { AsrBodySchema } from "./body-schema.ts";
export { composeAsr } from "./compose.ts";
export { checkAsrSubjectPresence } from "./subject-presence.ts";

// ── §8 cross-family composition surface (pure offline auditor) ─────────────────
export * from "./composition.ts";
export {
  ASR_CHANNELS,
  ASR_EVENT_TYPES,
  ASR_REFUSAL_GROUNDS,
  type AsrBody,
  type AsrChannel,
  type AsrClaimType,
  type AsrEventType,
  type AsrEscalatedBody,
  type AsrExtendedBody,
  type AsrFulfilledBody,
  type AsrIdentityVerifiedBody,
  type AsrPartiallyHonouredBody,
  type AsrProfile,
  type AsrRecipientNotifiedBody,
  type AsrRefusalGround,
  type AsrRefusedBody,
  type AsrRequestReceivedBody,
  type AsrScopeClarifiedBody,
} from "./types.ts";
