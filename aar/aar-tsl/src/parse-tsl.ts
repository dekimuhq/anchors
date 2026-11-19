/**
 * Parse a national TSL XML (ETSI TS 119 612) into TslServiceEntry[].
 *
 * Uses fast-xml-parser to extract TrustServiceProvider → TSPService →
 * ServiceInformation hierarchy. Maps ETSI service type URIs to AarServiceType.
 */

import * as crypto from "node:crypto";
import { XMLParser } from "fast-xml-parser";
import type { TslServiceEntry, TslServiceState } from "./types.ts";
import { SERVICE_TYPE_URI_MAP } from "./types.ts";

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  removeNSPrefix: true,
  isArray: (name) => {
    const arrayTags = new Set([
      "TrustServiceProvider",
      "TSPService",
      "DigitalId",
      "Name",
      "Extension",
      "QualificationElement",
      "Qualifier",
      "ServiceHistoryInstance",
    ]);
    return arrayTags.has(name);
  },
});

/** Extract the English name (or first name) from a Name element. */
function extractName(nameEl: unknown): string {
  if (!nameEl) return "";
  const names = Array.isArray(nameEl) ? nameEl : [nameEl];
  for (const n of names) {
    if (typeof n === "string") return n;
    if (typeof n === "object" && n !== null) {
      const obj = n as Record<string, unknown>;
      if (obj["@_xml:lang"] === "en" && typeof obj["#text"] === "string") {
        return obj["#text"];
      }
    }
  }
  // Fallback: first name with text
  for (const n of names) {
    if (typeof n === "object" && n !== null) {
      const obj = n as Record<string, unknown>;
      if (typeof obj["#text"] === "string") return obj["#text"];
    }
  }
  return "";
}

/** SHA-256 hex of the base64-decoded certificate bytes. */
function certHash(b64: string): string {
  const der = Buffer.from(b64.replace(/\s+/g, ""), "base64");
  return crypto.createHash("sha256").update(der).digest("hex");
}

/** Ensure value is an array. */
function toArray<T>(v: T | T[] | undefined | null): T[] {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

/** Text of a node that is either a bare string or `{ "#text": ..., "@_xml:lang": ... }`. */
function textOf(v: unknown): string {
  if (typeof v === "string") return v.trim();
  if (typeof v === "object" && v !== null) {
    const t = (v as Record<string, unknown>)["#text"];
    if (typeof t === "string") return t.trim();
  }
  return "";
}

/**
 * Read a `ServiceInformationExtensions` block: the `AdditionalServiceInformation` URIs and the `Qualifications`
 * qualifier URIs. Other extensions (and the qualification criteria) are ignored.
 */
function extractExtensions(ext: unknown): { additional_service_info: string[]; qualifiers: string[] } {
  const asi: string[] = [];
  const qualifiers: string[] = [];
  const list = toArray((ext as Record<string, unknown> | undefined)?.Extension);
  for (const e of list) {
    if (typeof e !== "object" || e === null) continue;
    const x = e as Record<string, unknown>;
    const info = x.AdditionalServiceInformation as Record<string, unknown> | undefined;
    for (const u of toArray(info?.URI)) {
      const t = textOf(u);
      if (t) asi.push(t);
    }
    const quals = x.Qualifications as Record<string, unknown> | undefined;
    for (const el of toArray(quals?.QualificationElement)) {
      const qs = (el as Record<string, unknown> | undefined)?.Qualifiers as Record<string, unknown> | undefined;
      for (const q of toArray(qs?.Qualifier)) {
        const uri = (q as Record<string, unknown> | undefined)?.["@_uri"];
        if (typeof uri === "string" && uri) qualifiers.push(uri);
      }
    }
  }
  return { additional_service_info: asi, qualifiers };
}

/**
 * Parse a national TSL XML and return all trust service entries.
 *
 * @param xml - raw XML string of a national Trusted List
 * @param country - ISO 3166-1 alpha-2 country code
 */
export function parseTsl(xml: string, country: string): TslServiceEntry[] {
  const doc = parser.parse(xml);
  const root = doc?.TrustServiceStatusList;
  if (!root) return [];

  const providerList = root?.TrustServiceProviderList;
  if (!providerList) return [];

  const providers = toArray(providerList.TrustServiceProvider);
  const entries: TslServiceEntry[] = [];

  for (const provider of providers) {
    const providerName = extractName(provider?.TSPInformation?.TSPName?.Name);
    const services = toArray(provider?.TSPServices?.TSPService);

    for (const svc of services) {
      const info = svc?.ServiceInformation;
      if (!info) continue;

      const serviceTypeId = String(info.ServiceTypeIdentifier ?? "");
      const serviceName = extractName(info?.ServiceName?.Name);
      const status = String(info.ServiceStatus ?? "");
      const statusStart = String(info.StatusStartingTime ?? "");

      // Extract certificate hashes from ServiceDigitalIdentity
      const hashes: string[] = [];
      const digitalIds = toArray(info?.ServiceDigitalIdentity?.DigitalId);
      for (const did of digitalIds) {
        if (typeof did === "object" && did !== null) {
          const obj = did as Record<string, unknown>;
          const cert = obj.X509Certificate;
          if (typeof cert === "string") {
            hashes.push(certHash(cert));
          }
        }
      }

      const now = extractExtensions(info.ServiceInformationExtensions);
      const history: TslServiceState[] = toArray(svc?.ServiceHistory?.ServiceHistoryInstance).map((h) => {
        const hi = h as Record<string, unknown>;
        const x = extractExtensions(hi.ServiceInformationExtensions);
        return { status: String(hi.ServiceStatus ?? ""), starting_time: String(hi.StatusStartingTime ?? ""), ...x };
      });

      entries.push({
        country,
        provider_name: providerName,
        service_type_identifier: serviceTypeId,
        service_type: SERVICE_TYPE_URI_MAP.get(serviceTypeId) ?? null,
        service_name: serviceName,
        status,
        status_starting_time: statusStart,
        certificate_hashes: hashes,
        additional_service_info: now.additional_service_info,
        qualifiers: now.qualifiers,
        status_history: history,
      });
    }
  }

  return entries;
}
