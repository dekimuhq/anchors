/**
 * `mintAsrV2` — thin re-export of `asrFamily.mintV2`.
 *
 * Phase 3 greenfield: the factory orchestrator (envelope `buildMintV2`)
 * owns the entire mint pipeline. ASR has no hand-rolled `keys.ts` — issuers
 * use `asrFamily.generateKeypair` directly, or import `generateKeypair`
 * from `@dekimuhq/anchors-envelope`.
 */

import { asrFamily } from "../family.ts";

export const mintAsrV2 = asrFamily.mintV2;
