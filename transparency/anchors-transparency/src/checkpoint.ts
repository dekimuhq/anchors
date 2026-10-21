import { signBytes, verifyBytes } from "./ed25519.ts";
import type { CheckpointNote } from "./types.ts";

/** The signed body: three header lines, each newline-terminated (C2SP note body). */
export function checkpointBody(c: Pick<CheckpointNote, "origin" | "size" | "rootHashB64">): string {
  return `${c.origin}\n${c.size}\n${c.rootHashB64}\n`;
}

export function signCheckpoint(
  c: Pick<CheckpointNote, "origin" | "size" | "rootHashB64">,
  keyHint: string,
  privateKeyPem: string,
): string {
  const body = checkpointBody(c);
  const sigB64 = signBytes(new TextEncoder().encode(body), privateKeyPem); // base64url
  return `${body}\n— ${keyHint} ${sigB64}\n`;
}

export function parseCheckpoint(note: string): CheckpointNote {
  const parts = note.split("\n\n");
  const head = parts[0] ?? "";
  const sigBlock = parts[1] ?? "";
  const lines = head.split("\n");
  if (lines.length < 3) throw new Error("malformed checkpoint head");
  const size = Number(lines[1]);
  if (!Number.isInteger(size) || size < 0) throw new Error("malformed checkpoint head: size must be a non-negative integer");
  const signatures = sigBlock
    .split("\n")
    .filter((l) => l.startsWith("— "))
    .map((l) => {
      const parts = l.slice(2).split(" "); // strip "— "
      return { keyHint: parts[0] ?? "", sigB64: parts[1] ?? "" };
    });
  return { origin: lines[0] ?? "", size, rootHashB64: lines[2] ?? "", signatures };
}

/** Verify at least the operator (first) signature against the supplied key map. */
export function verifyCheckpoint(note: string, keys: Record<string, string>): boolean {
  let parsed: CheckpointNote;
  try {
    parsed = parseCheckpoint(note);
  } catch {
    return false;
  }
  const bytes = new TextEncoder().encode(checkpointBody(parsed));
  const op = parsed.signatures[0];
  if (!op) return false;
  const pem = keys[op.keyHint];
  if (!pem) return false;
  return verifyBytes(op.sigB64, bytes, pem);
}
