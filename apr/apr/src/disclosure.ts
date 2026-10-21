/**
 * Disclosure projection per `apr-spec/v1.md` §6. Pure transform: takes a fully
 * verified `APRBody` and the desired tier, returns the body that should be
 * served to a public consumer.
 *
 * Downgrading at serve time is allowed; upgrading is not. Callers MAY pass a
 * `tier` that is more restrictive than `body.disclosure`, but MUST NOT pass
 * one that is less restrictive.
 */

import * as crypto from "node:crypto";
import type { APRBody, APRDisclosure, APRInputKind } from "./types.ts";

export interface DisclosedAprBody {
  artifact?: APRBody["artifact"];
  agent?: {
    kind: APRBody["agent"]["kind"];
    model?: string;
    provider?: string;
    humanRole?: APRBody["agent"]["humanRole"];
  };
  authorization?: {
    principalId?: string;
    principalPseudonym?: string;
  };
  inputs?: Array<{ kind: APRInputKind }>;
  startedAt?: number;
  completedAt?: number;
  durationMs?: number;
  disclosure: APRDisclosure;
  summary?: string;
  redacted: boolean;
}

const TIER_ORDER: Record<APRDisclosure, number> = {
  metadata_only: 0,
  public_minimal: 1,
  public_full: 2,
};

export function pseudonymise(principalId: string): string {
  const h = crypto.createHash("sha256").update(principalId, "utf8").digest("hex");
  return `u_${h.slice(0, 8)}`;
}

export function applyDisclosure(
  body: APRBody,
  tier: APRDisclosure = body.disclosure,
): DisclosedAprBody {
  if (TIER_ORDER[tier] > TIER_ORDER[body.disclosure]) {
    throw new Error(
      `applyDisclosure: cannot upgrade from "${body.disclosure}" to "${tier}"`,
    );
  }

  if (tier === "public_full") {
    return { ...body, redacted: false };
  }

  if (tier === "metadata_only") {
    return { disclosure: "metadata_only", redacted: true };
  }

  return {
    artifact: {
      type: body.artifact.type,
      id: body.artifact.id,
      hash: body.artifact.hash,
      hashAlgorithm: body.artifact.hashAlgorithm,
      ...(body.artifact.contentType !== undefined
        ? { contentType: body.artifact.contentType }
        : {}),
      ...(body.artifact.sizeBytes !== undefined
        ? { sizeBytes: body.artifact.sizeBytes }
        : {}),
    },
    agent: {
      kind: body.agent.kind,
      ...(body.agent.model !== undefined ? { model: body.agent.model } : {}),
      ...(body.agent.provider !== undefined
        ? { provider: body.agent.provider }
        : {}),
      ...(body.agent.humanRole !== undefined
        ? { humanRole: body.agent.humanRole }
        : {}),
    },
    authorization: {
      principalPseudonym: pseudonymise(body.authorization.principalId),
    },
    ...(body.inputs !== undefined
      ? { inputs: body.inputs.map((i) => ({ kind: i.kind })) }
      : {}),
    startedAt: body.startedAt,
    completedAt: body.completedAt,
    ...(body.durationMs !== undefined ? { durationMs: body.durationMs } : {}),
    disclosure: "public_minimal",
    redacted: true,
  };
}
