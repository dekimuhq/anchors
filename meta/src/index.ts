/**
 * `@dekimuhq/anchors` — meta-package for the Anchored Receipts family.
 *
 * For namespaced imports:
 *   import { apr, acr, acrProfiles, arr, arrProfiles, alr, alrProfiles, anr, anrProfiles, abr, abrProfiles, asr, asrProfiles, air, airProfiles, adr, adrProfiles, aer, aerProfiles, atr, atrProfiles, apur, apurProfiles, envelope, tsa, status } from "@dekimuhq/anchors";
 *   apr.mint(...); acr.mintConsent(...); arr.verifySingleReceipt(...); alr.mintDerivedFrom(...);
 *   anr.mintPresented(...); abr.mintDetected(...); asr.mintAsrV2(...); air.mintAirV2(...);
 *   envelope.signEnvelope(...); tsa.verifyTsa(...); status.verifyCredentialStatus(...);
 *
 * For surgical imports:
 *   import { mintDelegation } from "@dekimuhq/anchors/adr";
 *   import { validateGdprArt28Processor } from "@dekimuhq/anchors/adrProfiles";
 *   import { mintConsent } from "@dekimuhq/anchors/acr";
 *   import { validateGdprArt7 } from "@dekimuhq/anchors/acrProfiles";
 *   import { mint } from "@dekimuhq/anchors/apr";
 *   import { verifySingleReceipt } from "@dekimuhq/anchors/arr";
 *   import { validateGdprArt17 } from "@dekimuhq/anchors/arrProfiles";
 *   import { mintDerivedFrom, verifyReceipt } from "@dekimuhq/anchors/alr";
 *   import { validateGdprArt13Transparency } from "@dekimuhq/anchors/alrProfiles";
 *   import { mintPresented, verifyReceipt } from "@dekimuhq/anchors/anr";
 *   import { validateArt13CollectedDirect } from "@dekimuhq/anchors/anrProfiles";
 *   import { mintDetected, verifyReceipt } from "@dekimuhq/anchors/abr";
 *   import { validateGdprArt33 } from "@dekimuhq/anchors/abrProfiles";
 *   import { mintAsrV2, asrFamily } from "@dekimuhq/anchors/asr";
 *   import { validateArt15Access } from "@dekimuhq/anchors/asrProfiles";
 *   import { mintAirV2, verifyReceipt } from "@dekimuhq/anchors/air";
 *   import { validateImpactArt35_3_a } from "@dekimuhq/anchors/airProfiles";
 *   import { signEnvelope, canonicalize, canonicalizeEnvelope, verifyEnvelopeSignature } from "@dekimuhq/anchors/envelope";
 *   import { verifyTsa, buildTimeStampReq, loadTrustAnchors } from "@dekimuhq/anchors/tsa";
 *   import { fetchStatusListCredential, verifyCredentialStatus, attachCredentialStatus } from "@dekimuhq/anchors/status";
 */

export * as apr from "./apr.ts";
export * as acr from "./acr.ts";
export * as acrProfiles from "./acrProfiles.ts";
export * as arr from "./arr.ts";
export * as arrProfiles from "./arrProfiles.ts";
export * as alr from "./alr.ts";
export * as alrProfiles from "./alrProfiles.ts";
export * as anr from "./anr.ts";
export * as anrProfiles from "./anrProfiles.ts";
export * as abr from "./abr.ts";
export * as abrProfiles from "./abrProfiles.ts";
export * as asr from "./asr.ts";
export * as asrProfiles from "./asrProfiles.ts";
export * as air from "./air.ts";
export * as airProfiles from "./airProfiles.ts";
export * as atokr from "./atokr.ts";
export * as atokrProfiles from "./atokrProfiles.ts";
export * as aar from "./aar.ts";
export * as aarProfiles from "./aarProfiles.ts";
export * as adr from "./adr.ts";
export * as adrProfiles from "./adrProfiles.ts";
export * as aer from "./aer.ts";
export * as aerProfiles from "./aerProfiles.ts";
export * as atr from "./atr.ts";
export * as atrProfiles from "./atrProfiles.ts";
export * as apur from "./apur.ts";
export * as apurProfiles from "./apurProfiles.ts";
export * as envelope from "./envelope.ts";
export * as tsa from "./tsa.ts";
export * as status from "./status.ts";
export * as profile from "./profile.ts";
