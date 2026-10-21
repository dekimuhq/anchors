import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  fetchIssuerManifest,
  manifestUrlFromDid,
  ManifestFetchError,
  ManifestSchemaError,
} from "../src/fetch.ts";
import { makeSignedManifest, jsonFetcher } from "./fixtures.ts";

describe("fetchIssuerManifest", () => {
  it("fetches and parses a valid manifest", async () => {
    const { doc } = makeSignedManifest();
    const result = await fetchIssuerManifest({
      url: "https://test.example/.well-known/dekimu-issuer.json",
      fetcher: jsonFetcher(doc),
    });
    assert.equal(result.kind, "ar.issuer_manifest.v1");
    assert.equal(result.iss, "did:web:test-issuer.example");
  });

  it("throws ManifestFetchError on non-200", async () => {
    await assert.rejects(
      () => fetchIssuerManifest({
        url: "https://test.example/manifest.json",
        fetcher: jsonFetcher({}, 404),
      }),
      (err: unknown) => {
        assert.ok(err instanceof ManifestFetchError);
        assert.equal(err.code, "non_200");
        return true;
      },
    );
  });

  it("throws ManifestFetchError on network error", async () => {
    const fetcher = async () => { throw new Error("ECONNREFUSED"); };
    await assert.rejects(
      () => fetchIssuerManifest({ url: "https://test.example/x", fetcher }),
      (err: unknown) => {
        assert.ok(err instanceof ManifestFetchError);
        assert.equal(err.code, "network");
        return true;
      },
    );
  });

  it("throws ManifestFetchError on timeout", async () => {
    const fetcher = async (_url: string, init?: { signal?: AbortSignal }) => {
      return new Promise<Response>((_, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("abort")));
      });
    };
    await assert.rejects(
      () => fetchIssuerManifest({
        url: "https://test.example/x",
        fetcher,
        timeoutMs: 10,
      }),
      (err: unknown) => {
        assert.ok(err instanceof ManifestFetchError);
        assert.equal(err.code, "timeout");
        return true;
      },
    );
  });

  it("throws ManifestFetchError on malformed JSON", async () => {
    const fetcher = async () => new Response("not-json", { status: 200 });
    await assert.rejects(
      () => fetchIssuerManifest({ url: "https://test.example/x", fetcher }),
      (err: unknown) => {
        assert.ok(err instanceof ManifestFetchError);
        assert.equal(err.code, "malformed_json");
        return true;
      },
    );
  });

  it("throws ManifestFetchError on oversized response", async () => {
    const huge = "x".repeat(1_000_001);
    const fetcher = async () => new Response(huge, { status: 200 });
    await assert.rejects(
      () => fetchIssuerManifest({ url: "https://test.example/x", fetcher }),
      (err: unknown) => {
        assert.ok(err instanceof ManifestFetchError);
        assert.equal(err.code, "oversized_response");
        return true;
      },
    );
  });

  it("throws ManifestSchemaError on invalid schema", async () => {
    const fetcher = jsonFetcher({ kind: "wrong" });
    await assert.rejects(
      () => fetchIssuerManifest({ url: "https://test.example/x", fetcher }),
      (err: unknown) => {
        assert.ok(err instanceof ManifestSchemaError);
        return true;
      },
    );
  });

  it("throws ManifestFetchError on empty url", async () => {
    await assert.rejects(
      () => fetchIssuerManifest({ url: "" }),
      (err: unknown) => {
        assert.ok(err instanceof ManifestFetchError);
        assert.equal(err.code, "network");
        return true;
      },
    );
  });

  it("throws ManifestFetchError on body read failure", async () => {
    const fetcher = async () => {
      return {
        status: 200,
        text: async () => { throw new Error("stream error"); },
      } as unknown as Response;
    };
    await assert.rejects(
      () => fetchIssuerManifest({ url: "https://test.example/x", fetcher }),
      (err: unknown) => {
        assert.ok(err instanceof ManifestFetchError);
        assert.equal(err.code, "network");
        return true;
      },
    );
  });
});

describe("manifestUrlFromDid", () => {
  it("converts simple did:web to well-known URL", () => {
    assert.equal(
      manifestUrlFromDid("did:web:example.com"),
      "https://example.com/.well-known/dekimu-issuer.json",
    );
  });

  it("converts did:web with path to well-known URL", () => {
    assert.equal(
      manifestUrlFromDid("did:web:example.com:path:sub"),
      "https://example.com/path/sub/.well-known/dekimu-issuer.json",
    );
  });

  it("handles percent-encoded domain", () => {
    assert.equal(
      manifestUrlFromDid("did:web:example.com%3A8443"),
      "https://example.com:8443/.well-known/dekimu-issuer.json",
    );
  });

  it("throws on non-did:web", () => {
    assert.throws(() => manifestUrlFromDid("did:key:abc"), /expected did:web/);
  });

  it("throws on empty string", () => {
    assert.throws(() => manifestUrlFromDid(""), /expected did:web/);
  });
});
