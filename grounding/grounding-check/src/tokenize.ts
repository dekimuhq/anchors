/** Locked v1 tokenizer: lowercase, unicode-aware word split, no stemming. Single linear pass — no ReDoS surface. */
export function tokenize(text: string): string[] {
  const out = text.toLowerCase().match(/[\p{L}\p{N}]+/gu);
  return out ?? [];
}
