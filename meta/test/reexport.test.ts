import { test } from "node:test";
import assert from "node:assert/strict";
import * as apr from "../src/apr.ts";
import * as acr from "../src/acr.ts";
import * as acrProfiles from "../src/acrProfiles.ts";
import * as arr from "../src/arr.ts";
import * as arrProfiles from "../src/arrProfiles.ts";
import * as alr from "../src/alr.ts";
import * as alrProfiles from "../src/alrProfiles.ts";
import * as anr from "../src/anr.ts";
import * as anrProfiles from "../src/anrProfiles.ts";
import * as abr from "../src/abr.ts";
import * as abrProfiles from "../src/abrProfiles.ts";
import * as asr from "../src/asr.ts";
import * as asrProfiles from "../src/asrProfiles.ts";
import * as air from "../src/air.ts";
import * as airProfiles from "../src/airProfiles.ts";
import * as atokr from "../src/atokr.ts";
import * as atokrProfiles from "../src/atokrProfiles.ts";
import * as aar from "../src/aar.ts";
import * as aarProfiles from "../src/aarProfiles.ts";
import * as adr from "../src/adr.ts";
import * as adrProfiles from "../src/adrProfiles.ts";
import * as aer from "../src/aer.ts";
import * as aerProfiles from "../src/aerProfiles.ts";
import * as atr from "../src/atr.ts";
import * as atrProfiles from "../src/atrProfiles.ts";
import * as apur from "../src/apur.ts";
import * as apurProfiles from "../src/apurProfiles.ts";
import * as envelope from "../src/envelope.ts";
import * as tsa from "../src/tsa.ts";
import * as status from "../src/status.ts";
import * as both from "../src/index.ts";

test("anchors/apr re-exports apr-issuer-kit and apr-verifier symbols", () => {
  assert.equal(typeof apr.mint, "function");
  assert.equal(typeof apr.generateKeypair, "function");
});

test("anchors/acr re-exports acr-issuer-kit and acr-verifier symbols", () => {
  assert.equal(typeof acr.mintConsent, "function");
  assert.equal(typeof acr.mintModification, "function");
  assert.equal(typeof acr.mintWithdrawal, "function");
  assert.equal(typeof acr.verifyReceiptSignature, "function");
  assert.equal(typeof acr.resolveChainState, "function");
});

test("anchors/arr re-exports arr-issuer-kit and arr-verifier symbols", () => {
  assert.equal(typeof arr.verifySingleReceipt, "function");
  assert.equal(typeof arr.verifyBatchReceipt, "function");
  assert.equal(typeof arr.resolveTriggerReceipt, "function");
  assert.equal(typeof arr.verify30DayWindow, "function");
});

test("anchors/acrProfiles re-exports the gdpr.art7 and aiact.art14 validators", () => {
  assert.equal(typeof acrProfiles.validateGdprArt7, "function");
  assert.equal(typeof acrProfiles.validateAiActArt14, "function");
});

test("anchors/arrProfiles re-exports all 7 retention validators", () => {
  assert.equal(typeof arrProfiles.validateGdprArt17, "function");
  assert.equal(typeof arrProfiles.validateGdprArt5e, "function");
  assert.equal(typeof arrProfiles.validateHipaaRetention, "function");
  assert.equal(typeof arrProfiles.validateKycRetention, "function");
  assert.equal(typeof arrProfiles.validateSoxRetention, "function");
  assert.equal(typeof arrProfiles.validateMifid2Retention, "function");
  assert.equal(typeof arrProfiles.validateAiActArt10, "function");
});

test("anchors/index exposes all family namespaces", () => {
  assert.equal(typeof both.apr, "object");
  assert.equal(typeof both.acr, "object");
  assert.equal(typeof both.acrProfiles, "object");
  assert.equal(typeof both.arr, "object");
  assert.equal(typeof both.arrProfiles, "object");
  assert.equal(typeof both.alr, "object");
  assert.equal(typeof both.alrProfiles, "object");
  assert.equal(typeof both.anr, "object");
  assert.equal(typeof both.anrProfiles, "object");
  assert.equal(typeof both.abr, "object");
  assert.equal(typeof both.abrProfiles, "object");
  assert.equal(typeof both.asr, "object");
  assert.equal(typeof both.asrProfiles, "object");
  assert.equal(typeof both.air, "object");
  assert.equal(typeof both.airProfiles, "object");
  assert.equal(typeof both.atokr, "object");
  assert.equal(typeof both.atokrProfiles, "object");
  assert.equal(typeof both.aar, "object");
  assert.equal(typeof both.aarProfiles, "object");
  assert.equal(typeof both.adr, "object");
  assert.equal(typeof both.adrProfiles, "object");
  assert.equal(typeof both.aer, "object");
  assert.equal(typeof both.aerProfiles, "object");
  assert.equal(typeof both.atr, "object");
  assert.equal(typeof both.atrProfiles, "object");
  assert.equal(typeof both.apur, "object");
  assert.equal(typeof both.apurProfiles, "object");
  assert.equal(typeof both.apr.mint, "function");
  assert.equal(typeof both.acr.mintConsent, "function");
  assert.equal(typeof both.acrProfiles.validateGdprArt7, "function");
  assert.equal(typeof both.alr.mintDerivedFrom, "function");
  assert.equal(typeof both.alrProfiles.validateGdprArt13Transparency, "function");
  assert.equal(typeof both.anr.mintPresented, "function");
  assert.equal(typeof both.anrProfiles.validateArt13CollectedDirect, "function");
  assert.equal(typeof both.abr.mintDetected, "function");
  assert.equal(typeof both.abrProfiles.validateBreachGdprArt33, "function");
  assert.equal(typeof both.asr.mintAsrV2, "function");
  assert.equal(typeof both.asrProfiles.validateArt15Access, "function");
  assert.equal(typeof both.air.mintAirV2, "function");
  assert.equal(typeof both.airProfiles.validateImpactArt35_3_a, "function");
  assert.equal(typeof both.aer.mintAerV2, "function");
  assert.equal(typeof both.aerProfiles.validateAiactArt43Internal, "function");
  assert.equal(typeof both.atr.mintAtrV2, "function");
  assert.equal(typeof both.atrProfiles.validateGdprArt45Adequacy, "function");
  assert.equal(typeof both.apur.mintApurV2, "function");
  assert.equal(typeof both.apurProfiles.validateGdprArt5, "function");
});

test("anchors/alr re-exports alr-issuer-kit and alr-verifier symbols", () => {
  assert.equal(typeof alr.mintDerivedFrom, "function");
  assert.equal(typeof alr.mintForkedFrom, "function");
  assert.equal(typeof alr.mintSupersededBy, "function");
  assert.equal(typeof alr.mintDisclosed, "function");
  assert.equal(typeof alr.verifyReceipt, "function");
  assert.equal(typeof alr.issueContinuityAttestation, "function");
  assert.equal(typeof alr.verifyContinuityAttestation, "function");
});

test("anchors/alrProfiles re-exports all five ALR v1 profile validators", () => {
  assert.equal(typeof alrProfiles.validateGdprArt13Transparency, "function");
  assert.equal(typeof alrProfiles.validateAiactArt13Transparency, "function");
  assert.equal(typeof alrProfiles.validateAiactArt53GpaiTraining, "function");
  assert.equal(typeof alrProfiles.validateC2paNonMedia, "function");
  assert.equal(typeof alrProfiles.validateDisclosureRecipients, "function");
});

test("anchors/anr re-exports anr-issuer-kit and anr-verifier symbols", () => {
  assert.equal(typeof anr.mintPresented, "function");
  assert.equal(typeof anr.mintRePresented, "function");
  assert.equal(typeof anr.mintAcknowledged, "function");
  assert.equal(typeof anr.mintWithdrawn, "function");
  assert.equal(typeof anr.mintTranslated, "function");
  assert.equal(typeof anr.mintJointControllerEssence, "function");
  assert.equal(typeof anr.verifyReceipt, "function");
  assert.equal(typeof anr.issueContinuityAttestation, "function");
  assert.equal(typeof anr.verifyContinuityAttestation, "function");
});

test("anchors/anrProfiles re-exports all five ANR v1 profile validators", () => {
  assert.equal(typeof anrProfiles.validateArt13CollectedDirect, "function");
  assert.equal(typeof anrProfiles.validateArt14CollectedIndirect, "function");
  assert.equal(typeof anrProfiles.validateArt26JointControllerEssence, "function");
  assert.equal(typeof anrProfiles.validateLayeredTransparency, "function");
  assert.equal(typeof anrProfiles.validateAiactArt50Transparency, "function");
});

test("anchors/abr re-exports abr-issuer-kit and abr-verifier symbols", () => {
  assert.equal(typeof abr.mintAbrV2, "function");
  assert.equal(typeof abr.mintDetected, "function");
  assert.equal(typeof abr.mintAssessed, "function");
  assert.equal(typeof abr.mintDpaNotified, "function");
  assert.equal(typeof abr.mintDpaDelayed, "function");
  assert.equal(typeof abr.mintSubjectNotified, "function");
  assert.equal(typeof abr.mintSubjectNotificationExempted, "function");
  assert.equal(typeof abr.mintContained, "function");
  assert.equal(typeof abr.mintClosed, "function");
  assert.equal(typeof abr.verifyReceipt, "function");
  assert.equal(typeof abr.issueContinuityAttestation, "function");
  assert.equal(typeof abr.verifyContinuityAttestation, "function");
});

test("anchors/abrProfiles re-exports all five ABR v1 profile validators", () => {
  assert.equal(typeof abrProfiles.validateBreachGdprArt33, "function");
  assert.equal(typeof abrProfiles.validateBreachGdprArt34, "function");
  assert.equal(typeof abrProfiles.validateBreachNis2Art23, "function");
  assert.equal(typeof abrProfiles.validateBreachDoraArt19, "function");
  assert.equal(typeof abrProfiles.validateBreachUsStateAttorneyGeneral, "function");
});

test("anchors/asr re-exports asr-issuer-kit and asr-verifier symbols", () => {
  // Greenfield through defineFamily() — mint is family-bound (`asrFamily.mintV2`)
  // and re-exported by the issuer-kit as `mintAsrV2`.
  assert.equal(typeof asr.mintAsrV2, "function");
  assert.equal(typeof asr.generateKeypair, "function");
  assert.equal(typeof asr.asrFamily, "object");
  assert.equal(typeof asr.asrFamily.verifyReceipt, "function");
  assert.equal(typeof asr.asrFamily.mintV2, "function");
  // Frozen body-schema + subject-presence helpers also flow through.
  assert.equal(typeof asr.AsrBodySchema, "object");
  assert.equal(typeof asr.checkAsrSubjectPresence, "function");
});

test("anchors/air re-exports air-issuer-kit and air-verifier symbols", () => {
  // AIR is v=2-only — top-level `verifyReceipt` + `mintAirV2` + 11 per-event
  // wrappers. Continuity helpers flow through from the family-shared
  // `@dekimuhq/anchors-envelope/continuity` re-export inside air-issuer-kit.
  assert.equal(typeof air.verifyReceipt, "function");
  assert.equal(typeof air.mintAirV2, "function");
  assert.equal(typeof air.mintThresholdTriggered, "function");
  assert.equal(typeof air.mintScopeLocked, "function");
  assert.equal(typeof air.mintDpoAdvised, "function");
  assert.equal(typeof air.mintStakeholdersConsulted, "function");
  assert.equal(typeof air.mintCompleted, "function");
  assert.equal(typeof air.mintReviewed, "function");
  assert.equal(typeof air.mintPriorConsultationInitiated, "function");
  assert.equal(typeof air.mintPriorConsultationResolved, "function");
  assert.equal(typeof air.mintProcessingAuthorised, "function");
  assert.equal(typeof air.mintProcessingBlocked, "function");
  assert.equal(typeof air.mintTerminated, "function");
  assert.equal(typeof air.issueContinuityAttestation, "function");
  assert.equal(typeof air.verifyContinuityAttestation, "function");
  // Family-level invariants — TSA mandate matrix + subject-presence helpers.
  assert.equal(typeof air.applyAirTsaMandate, "function");
  assert.equal(typeof air.applyAirSubjectPresence, "function");
  assert.equal(typeof air.AIR_TSA_MANDATE, "object");
});

test("anchors/airProfiles re-exports all five AIR v1 profile validators", () => {
  assert.equal(typeof airProfiles.validateImpactArt35_3_a, "function");
  assert.equal(typeof airProfiles.validateImpactArt35_3_b, "function");
  assert.equal(typeof airProfiles.validateImpactArt35_3_c, "function");
  assert.equal(typeof airProfiles.validateImpactArt35_4, "function");
  assert.equal(typeof airProfiles.validateImpactVoluntary, "function");
  // Profile registry + dispatcher surface.
  assert.equal(typeof airProfiles.getAirProfileValidator, "function");
  assert.equal(typeof airProfiles.validateAirProfile, "function");
});

test("anchors/asrProfiles re-exports all six ASR v1 profile validators", () => {
  assert.equal(typeof asrProfiles.validateArt15Access, "function");
  assert.equal(typeof asrProfiles.validateArt16Rectification, "function");
  assert.equal(typeof asrProfiles.validateArt17ErasureRequest, "function");
  assert.equal(typeof asrProfiles.validateArt18Restriction, "function");
  assert.equal(typeof asrProfiles.validateArt20Portability, "function");
  assert.equal(typeof asrProfiles.validateArt21Objection, "function");
  // Envelope-shaped adapters surfaced for direct registry wiring.
  assert.equal(typeof asrProfiles.validateArt15AccessProfile, "function");
  assert.equal(typeof asrProfiles.validateArt17ErasureRequestProfile, "function");
});

test("anchors/atokr re-exports atokr-issuer-kit and atokr-verifier symbols", () => {
  assert.equal(typeof atokr.verifyReceipt, "function");
  assert.equal(typeof atokr.issueContinuityAttestation, "function");
});

test("anchors/atokrProfiles re-exports ATokR v1 profile validators", () => {
  assert.equal(typeof atokrProfiles.validateGdprArt32, "function");
  assert.equal(typeof atokrProfiles.validatePciDssV4, "function");
  assert.equal(typeof atokrProfiles.validateEudiWalletArf, "function");
});

test("anchors/aar re-exports aar-issuer-kit and aar-verifier symbols", () => {
  assert.equal(typeof aar.verifyReceipt, "function");
  assert.equal(typeof aar.issueContinuityAttestation, "function");
});

test("anchors/aarProfiles re-exports all eight AAR eIDAS profile validators", () => {
  assert.equal(typeof aarProfiles.validateEidasQes, "function");
  assert.equal(typeof aarProfiles.validateEidasQeseal, "function");
  assert.equal(typeof aarProfiles.validateEidasQts, "function");
  assert.equal(typeof aarProfiles.validateEidasQereg, "function");
  assert.equal(typeof aarProfiles.validateEidasQcertNatural, "function");
  assert.equal(typeof aarProfiles.validateEidasQcertLegal, "function");
  assert.equal(typeof aarProfiles.validateEidasQwallet, "function");
  assert.equal(typeof aarProfiles.validateEidasQattest, "function");
});

test("anchors/adr re-exports adr-issuer-kit and adr-verifier symbols", () => {
  assert.equal(typeof adr.adrFamily, "object");
  assert.equal(typeof adr.mintAdrV2, "function");
  assert.equal(typeof adr.walkDelegationTree, "function");
  assert.equal(typeof adr.issueContinuityAttestation, "function");
});

test("anchors/adrProfiles re-exports all five ADR v1 profile validators", () => {
  assert.equal(typeof adrProfiles.validateAiactArt26Deployer, "function");
  assert.equal(typeof adrProfiles.validateAiactArt14Oversight, "function");
  assert.equal(typeof adrProfiles.validateGdprArt28Processor, "function");
  assert.equal(typeof adrProfiles.validateCorporateOfficer, "function");
  assert.equal(typeof adrProfiles.validateAgentopsScopedDelegation, "function");
});

test("anchors/aer re-exports aer-issuer-kit and aer-verifier symbols", () => {
  assert.equal(typeof aer.verifyReceipt, "function");
  assert.equal(typeof aer.mintAerV2, "function");
  assert.equal(typeof aer.mintConformity, "function");
  assert.equal(typeof aer.mintTransparency, "function");
  assert.equal(typeof aer.issueContinuityAttestation, "function");
});

test("anchors/aerProfiles re-exports AER v1 profile validators", () => {
  assert.equal(typeof aerProfiles.validateAiactArt43Internal, "function");
  assert.equal(typeof aerProfiles.validateAiactArt43Thirdparty, "function");
  assert.equal(typeof aerProfiles.validateAiactArt43FrAssessment, "function");
  assert.equal(typeof aerProfiles.validateAiactArt50Chatbot, "function");
  assert.equal(typeof aerProfiles.validateAiactArt50SyntheticMedia, "function");
  assert.equal(typeof aerProfiles.validateAiactArt50EmotionBiocategorization, "function");
  assert.equal(typeof aerProfiles.validateAiactArt50PublicText, "function");
  assert.equal(typeof aerProfiles.validateAiactArt52Gpai, "function");
  assert.equal(typeof aerProfiles.validateNistAimrf, "function");
});

test("anchors/atr re-exports atr-issuer-kit and atr-verifier symbols", () => {
  assert.equal(typeof atr.verifyReceipt, "function");
  assert.equal(typeof atr.mintAtrV2, "function");
  assert.equal(typeof atr.mintArrangement, "function");
  assert.equal(typeof atr.mintTransfer, "function");
  assert.equal(typeof atr.mintTia, "function");
  assert.equal(typeof atr.mintSuspension, "function");
  assert.equal(typeof atr.issueContinuityAttestation, "function");
});

test("anchors/atrProfiles re-exports ATR v1 profile validators", () => {
  assert.equal(typeof atrProfiles.validateGdprArt45Adequacy, "function");
  assert.equal(typeof atrProfiles.validateGdprArt46Scc, "function");
  assert.equal(typeof atrProfiles.validateGdprArt46Bcr, "function");
  assert.equal(typeof atrProfiles.validateGdprArt46Idta, "function");
  assert.equal(typeof atrProfiles.validateGdprArt47BcrAuthorised, "function");
  assert.equal(typeof atrProfiles.validateGdprArt49Derogation, "function");
  assert.equal(typeof atrProfiles.validateGdprDpf, "function");
  assert.equal(typeof atrProfiles.validateSchremsiiTia, "function");
});

test("anchors/apur re-exports apur-issuer-kit and apur-verifier symbols", () => {
  assert.equal(typeof apur.verifyReceipt, "function");
  assert.equal(typeof apur.mintApurV2, "function");
  assert.equal(typeof apur.mintBinding, "function");
  assert.equal(typeof apur.mintRepurpose, "function");
  assert.equal(typeof apur.mintUnbinding, "function");
  assert.equal(typeof apur.issueContinuityAttestation, "function");
});

test("anchors/apurProfiles re-exports APuR v1 profile validators", () => {
  assert.equal(typeof apurProfiles.validateGdprArt5, "function");
  assert.equal(typeof apurProfiles.validateGdprArt6_4, "function");
  assert.equal(typeof apurProfiles.validateHipaaMinimumNecessary, "function");
  assert.equal(typeof apurProfiles.validateLgpdArt6, "function");
});

test("anchors/envelope re-exports envelope layer symbols", () => {
  assert.equal(typeof envelope.signEnvelope, "function");
  assert.equal(typeof envelope.canonicalize, "function");
  assert.equal(typeof envelope.canonicalizeEnvelope, "function");
  assert.equal(typeof envelope.verifyEnvelopeSignature, "function");
});

test("anchors/tsa re-exports RFC 3161 + EUTL trust-anchor catalog symbols", () => {
  assert.equal(typeof tsa.verifyTsa, "function");
  assert.equal(typeof tsa.buildTimeStampReq, "function");
  assert.equal(typeof tsa.loadTrustAnchors, "function");
});

test("anchors/status re-exports W3C Status List 2021 symbols", () => {
  assert.equal(typeof status.fetchStatusListCredential, "function");
  assert.equal(typeof status.verifyCredentialStatus, "function");
  assert.equal(typeof status.attachCredentialStatus, "function");
  assert.equal(typeof status.MAX_STATUS_INDEX, "number");
});

test("anchors/envelope re-exports v1.2 surface (Phase E5)", () => {
  // Runtime exports — must resolve to functions/values.
  assert.equal(typeof envelope.JSON_LOGIC_ALLOWLIST_V1_2, "object");
  assert.ok(
    Array.isArray(envelope.JSON_LOGIC_ALLOWLIST_V1_2),
    "JSON_LOGIC_ALLOWLIST_V1_2 must be an array",
  );
  assert.ok(
    envelope.JSON_LOGIC_ALLOWLIST_V1_2.length === 27,
    `JSON_LOGIC_ALLOWLIST_V1_2 should have 27 operators (spec §5.1); got ${envelope.JSON_LOGIC_ALLOWLIST_V1_2.length}`,
  );
  assert.equal(typeof envelope.validatePredicate, "function");
  assert.equal(typeof envelope.evaluatePredicate, "function");
  assert.equal(typeof envelope.checkIatMs, "function");
  assert.equal(typeof envelope.checkPredicate, "function");
});

test("anchors/envelope v1.2 type aliases compile-resolve (Phase E5)", () => {
  // Type-only smoke: declared aliases must compile-resolve. Erased at runtime;
  // assignment proves the names resolve at the type level via the meta barrel.
  type _Kind = envelope.Kind;
  type _Cause = envelope.Cause;
  type _JsonLogicAst = envelope.JsonLogicAst;
  type _PredicateReasonCode = envelope.PredicateReasonCode;
  // Use one runtime value to keep the test non-vacuous.
  const k: envelope.Kind = "decision";
  assert.equal(k, "decision");
});

test("anchors/index exposes envelope/tsa/status namespaces", () => {
  assert.equal(typeof both.envelope, "object");
  assert.equal(typeof both.tsa, "object");
  assert.equal(typeof both.status, "object");
  assert.equal(typeof both.envelope.signEnvelope, "function");
  assert.equal(typeof both.envelope.canonicalize, "function");
  assert.equal(typeof both.envelope.canonicalizeEnvelope, "function");
  assert.equal(typeof both.envelope.verifyEnvelopeSignature, "function");
  assert.equal(typeof both.tsa.verifyTsa, "function");
  assert.equal(typeof both.tsa.buildTimeStampReq, "function");
  assert.equal(typeof both.tsa.loadTrustAnchors, "function");
  assert.equal(typeof both.status.fetchStatusListCredential, "function");
  assert.equal(typeof both.status.verifyCredentialStatus, "function");
  assert.equal(typeof both.status.attachCredentialStatus, "function");
  assert.equal(typeof both.status.MAX_STATUS_INDEX, "number");
});
