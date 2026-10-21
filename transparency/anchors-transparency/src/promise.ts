import { signBytes, verifyBytes } from "./ed25519.ts";
import type { InclusionPromise } from "./types.ts";

function promiseBytes(logId: string, leaf: string, timestamp: string): Uint8Array {
  return new TextEncoder().encode(`${logId}\n${leaf}\n${timestamp}`);
}

/** Returns the base64url Ed25519 signature for the promise tuple (log_id‖leaf‖timestamp). */
export function signPromise(logId: string, leaf: string, timestamp: string, privateKeyPem: string): string {
  return signBytes(promiseBytes(logId, leaf, timestamp), privateKeyPem);
}

export function verifyPromise(
  logId: string,
  leaf: string,
  promise: InclusionPromise,
  keys: Record<string, string>,
): boolean {
  const pem = keys[logId];
  if (!pem) return false;
  return verifyBytes(promise.sig, promiseBytes(logId, leaf, promise.timestamp), pem);
}
