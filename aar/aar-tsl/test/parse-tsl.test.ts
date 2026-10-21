import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { parseTsl } from "../src/parse-tsl.ts";

const FIXTURE = readFileSync(
  new URL("./fixtures/national-tsl-es.xml", import.meta.url),
  "utf8",
);

describe("parseTsl", () => {
  it("extracts all 3 services from fixture", () => {
    const entries = parseTsl(FIXTURE, "ES");
    assert.equal(entries.length, 3);
  });

  it("populates country from argument", () => {
    const entries = parseTsl(FIXTURE, "ES");
    for (const e of entries) {
      assert.equal(e.country, "ES");
    }
  });

  it("extracts provider names", () => {
    const entries = parseTsl(FIXTURE, "ES");
    const names = entries.map((e) => e.provider_name);
    assert.ok(names.includes("Firmaprofesional SA"));
    assert.ok(names.includes("FNMT-RCM"));
  });

  it("maps QCertESig URI to qes", () => {
    const entries = parseTsl(FIXTURE, "ES");
    const qes = entries.find((e) => e.service_type === "qes");
    assert.ok(qes);
    assert.equal(qes.service_type_identifier, "http://uri.etsi.org/TrstSvc/Svctype/QCertESig");
  });

  it("maps TSA/QTST URI to qts", () => {
    const entries = parseTsl(FIXTURE, "ES");
    const qts = entries.find((e) => e.service_type === "qts");
    assert.ok(qts);
  });

  it("maps QCertESeal URI to qeseal", () => {
    const entries = parseTsl(FIXTURE, "ES");
    const qeseal = entries.find((e) => e.service_type === "qeseal");
    assert.ok(qeseal);
    assert.equal(qeseal.status, "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn");
  });

  it("extracts status_starting_time", () => {
    const entries = parseTsl(FIXTURE, "ES");
    const qes = entries.find((e) => e.service_type === "qes")!;
    assert.equal(qes.status_starting_time, "2016-07-01T00:00:00Z");
  });

  it("computes certificate hashes", () => {
    const entries = parseTsl(FIXTURE, "ES");
    for (const e of entries) {
      assert.ok(e.certificate_hashes.length > 0);
      for (const h of e.certificate_hashes) {
        assert.equal(h.length, 64); // hex SHA-256
      }
    }
  });

  it("returns empty array for XML with no providers", () => {
    const empty = `<?xml version="1.0"?><TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><TrustServiceProviderList/></TrustServiceStatusList>`;
    const entries = parseTsl(empty, "ES");
    assert.equal(entries.length, 0);
  });

  it("handles unknown service type URI gracefully", () => {
    const xml = FIXTURE.replace(
      "http://uri.etsi.org/TrstSvc/Svctype/QCertESig",
      "http://uri.etsi.org/TrstSvc/Svctype/Unknown",
    );
    const entries = parseTsl(xml, "ES");
    const unknown = entries.find((e) => e.service_type_identifier.includes("Unknown"));
    assert.ok(unknown);
    assert.equal(unknown.service_type, null);
  });
});
