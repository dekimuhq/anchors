import * as crypto from "node:crypto";
import {
  canonicalize,
  base64UrlEncode,
  commit,
  randomSalt,
  buildTree,
  hashReceipt,
  type ACRReceipt,
  type AcrProfile,
} from "../index.ts";
import { encodeRaw, type Keypair } from "./keys.ts";

const PKCS8_ED25519_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

interface FieldInput {
  /** Plaintext value to commit (will be salted). */
  value: string;
  /** Optional pre-existing salt. If absent, a fresh one is generated. */
  salt?: string;
}

interface MintFields {
  sub_commit: FieldInput;
  purposes: FieldInput[];
  policy_hash: FieldInput;
}

interface MintConsentInput {
  issuerDid: string;
  signingKey: Keypair;
  profile: AcrProfile;
  fields: MintFields;
  lawful_basis: string;
  granted_at: string;
  expires_at?: string;
  /** Include the salts used (issuer needs them to later prove disclosures). */
  returnSalts?: boolean;
}

interface MintModificationInput {
  prior: ACRReceipt;
  signingKey: Keypair;
  fields: MintFields;
  lawful_basis: string;
  granted_at: string;
  expires_at?: string;
  returnSalts?: boolean;
}

interface MintWithdrawalInput {
  prior: ACRReceipt;
  signingKey: Keypair;
  granted_at: string;
}

export interface SaltBundle {
  sub_commit: string;
  purposes: string[];
  policy_hash: string;
}

interface MintResult extends ACRReceipt {
  salts?: SaltBundle;
}

function sign(receipt: ACRReceipt, sk: Uint8Array): string {
  const signedView = { ...receipt, anchor: null, sig: null, countersig: null };
  const bytes = new TextEncoder().encode(canonicalize(signedView));
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(sk)]);
  const skKey = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const sig = crypto.sign(null, bytes, skKey);
  return `ed25519:${base64UrlEncode(new Uint8Array(sig))}`;
}

function buildFromFields(fields: MintFields): {
  sub_commit: string;
  purposes: string[];
  policy_hash: string;
  field_root: string;
  salts: SaltBundle;
} {
  const subSalt = fields.sub_commit.salt ?? randomSalt();
  const sub_commit = commit(subSalt, fields.sub_commit.value);

  const purposeSalts = fields.purposes.map((p) => p.salt ?? randomSalt());
  const purposes = fields.purposes.map((p, i) => commit(purposeSalts[i]!, p.value));

  const polSalt = fields.policy_hash.salt ?? randomSalt();
  const policy_hash = commit(polSalt, fields.policy_hash.value);

  // Field root: Merkle over sub_commit + each purpose + policy_hash in fixed order.
  const leaves = [sub_commit, ...purposes, policy_hash];
  const { root: field_root } = buildTree(leaves);

  return {
    sub_commit,
    purposes,
    policy_hash,
    field_root,
    salts: { sub_commit: subSalt, purposes: purposeSalts, policy_hash: polSalt },
  };
}

export function mintConsent(input: MintConsentInput): MintResult {
  const built = buildFromFields(input.fields);
  const receipt: ACRReceipt = {
    kind: "ar.consent.v1",
    profile: input.profile,
    iss: input.issuerDid,
    iss_key: `ed25519:${encodeRaw(input.signingKey.publicKey)}`,
    sub_commit: built.sub_commit,
    purposes: built.purposes,
    lawful_basis: input.lawful_basis,
    policy_hash: built.policy_hash,
    granted_at: input.granted_at,
    ...(input.expires_at !== undefined ? { expires_at: input.expires_at } : {}),
    prev: null,
    field_root: built.field_root,
    anchor: null,
    sig: "",
    countersig: null,
    qts_attestation_hash: null,
  };
  receipt.sig = sign(receipt, input.signingKey.privateKey);
  return input.returnSalts ? { ...receipt, salts: built.salts } : receipt;
}

export function mintModification(input: MintModificationInput): MintResult {
  const built = buildFromFields(input.fields);
  const receipt: ACRReceipt = {
    kind: "ar.modification.v1",
    profile: input.prior.profile,
    iss: input.prior.iss,
    iss_key: `ed25519:${encodeRaw(input.signingKey.publicKey)}`,
    sub_commit: built.sub_commit,
    purposes: built.purposes,
    lawful_basis: input.lawful_basis,
    policy_hash: built.policy_hash,
    granted_at: input.granted_at,
    ...(input.expires_at !== undefined ? { expires_at: input.expires_at } : {}),
    prev: hashReceipt(input.prior),
    field_root: built.field_root,
    anchor: null,
    sig: "",
    countersig: null,
    qts_attestation_hash: null,
  };
  receipt.sig = sign(receipt, input.signingKey.privateKey);
  return input.returnSalts ? { ...receipt, salts: built.salts } : receipt;
}

export function mintWithdrawal(input: MintWithdrawalInput): ACRReceipt {
  // Withdrawal preserves committed identifiers from the prior receipt;
  // no new field values are introduced. The field_root is recomputed
  // over the same commitments so verifiers can still walk a clean tree.
  const leaves = [
    input.prior.sub_commit,
    ...input.prior.purposes,
    input.prior.policy_hash,
  ];
  const { root: field_root } = buildTree(leaves);

  const receipt: ACRReceipt = {
    kind: "ar.withdrawal.v1",
    profile: input.prior.profile,
    iss: input.prior.iss,
    iss_key: `ed25519:${encodeRaw(input.signingKey.publicKey)}`,
    sub_commit: input.prior.sub_commit,
    purposes: input.prior.purposes,
    lawful_basis: input.prior.lawful_basis,
    policy_hash: input.prior.policy_hash,
    granted_at: input.granted_at,
    prev: hashReceipt(input.prior),
    field_root,
    anchor: null,
    sig: "",
    countersig: null,
    qts_attestation_hash: null,
  };
  receipt.sig = sign(receipt, input.signingKey.privateKey);
  return receipt;
}
