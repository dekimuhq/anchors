import { canonicalize } from "@dekimuhq/anchors-envelope";
import { hashLeaf } from "./rfc6962.ts";

/** RFC 6962 leaf hash over JCS(receipt \ {incl}). Returns "sha256:<hex>". */
export function leafHash(receipt: Record<string, unknown>): string {
  const { incl: _omit, ...rest } = receipt;
  const bytes = Buffer.from(canonicalize(rest), "utf8");
  return `sha256:${hashLeaf(bytes).toString("hex")}`;
}
