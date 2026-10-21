/**
 * Fetch and parse the EU List of Trusted Lists (LOTL).
 *
 * Public API:
 *   fetchLotl() — fetch LOTL XML from EU, return national TSL pointers
 *   parseLotl(xml) — parse LOTL XML string (exported for testing)
 */

import { XMLParser } from "fast-xml-parser";
import type { NationalTslPointer } from "./types.ts";

const LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
const FETCH_TIMEOUT_MS = 15_000;

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  removeNSPrefix: true,
  isArray: (name) => name === "OtherTSLPointer" || name === "OtherInformation",
});

function toArray<T>(v: T | T[] | undefined | null): T[] {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

/**
 * Parse LOTL XML and extract national TSL pointers.
 * Exported for unit testing with fixtures.
 */
export function parseLotl(xml: string): NationalTslPointer[] {
  const doc = parser.parse(xml);
  const root = doc?.TrustServiceStatusList;
  if (!root) return [];

  const ptrs = root?.SchemeInformation?.PointersToOtherTSL;
  if (!ptrs) return [];

  const pointers = toArray(ptrs.OtherTSLPointer);
  const result: NationalTslPointer[] = [];

  for (const ptr of pointers) {
    const url = String(ptr?.TSLLocation ?? "");
    if (!url) continue;

    // Extract SchemeTerritory from AdditionalInformation → OtherInformation
    const otherInfos = toArray(ptr?.AdditionalInformation?.OtherInformation);
    let country = "";
    for (const oi of otherInfos) {
      if (typeof oi === "object" && oi !== null) {
        const obj = oi as Record<string, unknown>;
        if (typeof obj.SchemeTerritory === "string") {
          country = obj.SchemeTerritory;
          break;
        }
      }
    }

    if (country && url.startsWith("http")) {
      result.push({ country, url });
    }
  }

  return result;
}

/**
 * Fetch the LOTL from the EU Commission and return national TSL pointers.
 * Throws on HTTP failure or timeout.
 */
export async function fetchLotl(): Promise<NationalTslPointer[]> {
  const res = await fetch(LOTL_URL, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) {
    throw new Error(`fetchLotl: HTTP ${res.status} from ${LOTL_URL}`);
  }
  const xml = await res.text();
  return parseLotl(xml);
}
