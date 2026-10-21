/** ACR re-exports — `import { mintConsent } from "@dekimuhq/anchors/acr"`. */
export * from "@dekimuhq/acr";
export {
  mintConsent,
  mintModification,
  mintWithdrawal,
  generateKeypair,
  publicKeyFromSeed,
  encodeRaw,
  decodeRaw32,
  buildDisclosureProof,
} from "@dekimuhq/acr/issue";
export type { Keypair } from "@dekimuhq/acr/issue";
