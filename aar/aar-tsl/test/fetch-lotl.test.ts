import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { parseLotl } from "../src/fetch-lotl.ts";

const FIXTURE = readFileSync(
  new URL("./fixtures/lotl.xml", import.meta.url),
  "utf8",
);

describe("parseLotl", () => {
  it("extracts 3 national TSL pointers from fixture", () => {
    const pointers = parseLotl(FIXTURE);
    assert.equal(pointers.length, 3);
  });

  it("extracts country codes", () => {
    const pointers = parseLotl(FIXTURE);
    const countries = pointers.map((p) => p.country);
    assert.deepEqual(countries.sort(), ["DE", "ES", "IT"]);
  });

  it("extracts URLs", () => {
    const pointers = parseLotl(FIXTURE);
    const es = pointers.find((p) => p.country === "ES")!;
    assert.ok(es.url.includes("sede.minetur.gob.es"));
  });

  it("returns empty array for XML with no pointers", () => {
    const empty = `<?xml version="1.0"?><TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><SchemeInformation/></TrustServiceStatusList>`;
    const pointers = parseLotl(empty);
    assert.equal(pointers.length, 0);
  });
});
