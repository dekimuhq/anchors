import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { didWebToUrl, DidWebResolveError } from "../src/index.ts";

describe("didWebToUrl", () => {
  it("maps did:web:domain → https://domain/.well-known/dekimu-keys.json", () => {
    const url = didWebToUrl("did:web:competitor.com");
    assert.equal(url.href, "https://competitor.com/.well-known/dekimu-keys.json");
  });

  it("maps did:web:domain:path:nested → https://domain/path/nested/.well-known/dekimu-keys.json", () => {
    const url = didWebToUrl("did:web:example.com:user:alice");
    assert.equal(url.href, "https://example.com/user/alice/.well-known/dekimu-keys.json");
  });

  it("URL-decodes percent-encoded path segments per W3C did:web v1.0", () => {
    const url = didWebToUrl("did:web:example.com:org%3A42");
    assert.equal(url.pathname, "/org:42/.well-known/dekimu-keys.json");
  });

  it("rejects non-did:web inputs", () => {
    assert.throws(
      () => didWebToUrl("did:key:z6Mkf..."),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "unsupported_did_method",
    );
  });

  it("rejects empty domain", () => {
    assert.throws(
      () => didWebToUrl("did:web:"),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "invalid_did",
    );
  });
});
