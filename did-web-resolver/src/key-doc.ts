import { DidWebResolveError } from "./errors.ts";

export interface KeyEntryV1 {
  iss_key: string;
  public_key_der_base64: string;
  valid_from: string;
  valid_until: string | null;
}

export interface KeyDocV1 {
  version: 1;
  keys: KeyEntryV1[];
}

function isStringField(o: Record<string, unknown>, k: string): boolean {
  return typeof o[k] === "string" && (o[k] as string).length > 0;
}

function reject(msg: string): never {
  throw new DidWebResolveError("key_doc_invalid", msg);
}

export function parseKeyDoc(input: unknown): KeyDocV1 {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    reject("root must be a JSON object");
  }
  const doc = input as Record<string, unknown>;
  if (doc.version !== 1) {
    reject(`version must be 1 (got: ${JSON.stringify(doc.version)})`);
  }
  if (!Array.isArray(doc.keys)) {
    reject("keys must be an array");
  }
  const keys: KeyEntryV1[] = [];
  const rawKeys = doc.keys as unknown[];
  for (let i = 0; i < rawKeys.length; i++) {
    const raw = rawKeys[i];
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      reject(`keys[${i}] must be an object`);
    }
    const entry = raw as Record<string, unknown>;
    if (!isStringField(entry, "iss_key")) reject(`keys[${i}].iss_key required (string)`);
    if (!isStringField(entry, "public_key_der_base64")) {
      reject(`keys[${i}].public_key_der_base64 required (string)`);
    }
    if (!isStringField(entry, "valid_from")) reject(`keys[${i}].valid_from required (ISO string)`);
    const validUntil = entry.valid_until;
    if (validUntil !== null && typeof validUntil !== "string") {
      reject(`keys[${i}].valid_until must be null or ISO string`);
    }
    keys.push({
      iss_key: entry.iss_key as string,
      public_key_der_base64: entry.public_key_der_base64 as string,
      valid_from: entry.valid_from as string,
      valid_until: validUntil as string | null,
    });
  }
  return { version: 1, keys };
}
