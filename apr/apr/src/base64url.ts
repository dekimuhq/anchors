export function base64UrlDecode(s: string): Uint8Array {
  if (typeof s !== "string") {
    throw new Error("base64UrlDecode: expected string");
  }
  return new Uint8Array(Buffer.from(s, "base64url"));
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}
