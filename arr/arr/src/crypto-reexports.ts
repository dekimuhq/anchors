export {
  canonicalize,
  base64UrlEncode,
  base64UrlDecode,
} from "@dekimuhq/anchors-envelope";

export {
  commit,
  verifyCommitment,
  randomSalt,
  buildTree,
  inclusionProof,
  verifyInclusion,
} from "@dekimuhq/acr";

export type { MerkleTree } from "@dekimuhq/acr";
