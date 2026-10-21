import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { hashEntry } from "../src/canonicalize.ts";
import type { TslServiceEntry } from "../src/types.ts";

describe("canonicalize", () => {
  const entry: TslServiceEntry = {
    country: "ES",
    provider_name: "Test QTSP",
    service_type_identifier: "http://uri.etsi.org/TrstSvc/Svctype/QCertESig",
    service_type: "qes",
    service_name: "QES Service",
    status: "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
    status_starting_time: "2025-01-01T00:00:00Z",
    certificate_hashes: ["abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"],
  };

  it("returns sha256-prefixed hash", () => {
    const h = hashEntry(entry);
    assert.ok(h.startsWith("sha256:"));
    assert.equal(h.length, 7 + 64);
  });

  it("is deterministic", () => {
    assert.equal(hashEntry(entry), hashEntry(entry));
  });

  it("is deterministic regardless of field order", () => {
    const reordered: TslServiceEntry = {
      status_starting_time: entry.status_starting_time,
      certificate_hashes: entry.certificate_hashes,
      country: entry.country,
      service_type: entry.service_type,
      service_name: entry.service_name,
      provider_name: entry.provider_name,
      service_type_identifier: entry.service_type_identifier,
      status: entry.status,
    };
    assert.equal(hashEntry(entry), hashEntry(reordered));
  });

  it("different entries produce different hashes", () => {
    const other: TslServiceEntry = { ...entry, country: "DE" };
    assert.notEqual(hashEntry(entry), hashEntry(other));
  });

  it("different service types produce different hashes", () => {
    const other: TslServiceEntry = { ...entry, service_type: "qts" };
    assert.notEqual(hashEntry(entry), hashEntry(other));
  });

  it("null service_type is canonical", () => {
    const withNull: TslServiceEntry = { ...entry, service_type: null };
    const h = hashEntry(withNull);
    assert.ok(h.startsWith("sha256:"));
    assert.notEqual(h, hashEntry(entry));
  });
});
