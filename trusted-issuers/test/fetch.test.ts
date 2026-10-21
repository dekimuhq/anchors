import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  fetchTrustedIssuers,
  TrustedIssuersFetchError,
  TrustedIssuersSchemaError,
} from "../src/index.ts";
import { makeSignedDoc, jsonFetcher } from "./fixtures.ts";

const URL = "https://dekimu.com/.well-known/trusted-issuers.json";

describe("fetchTrustedIssuers — happy path", () => {
  it("returns the parsed doc on 200", async () => {
    const { doc } = makeSignedDoc();
    const out = await fetchTrustedIssuers({
      url: URL,
      fetcher: jsonFetcher(doc),
    });
    assert.equal(out.kind, "ar.trusted_issuers.v1");
    assert.equal(out.publisher, doc.publisher);
  });

  it("passes the url to the injected fetcher", async () => {
    const { doc } = makeSignedDoc();
    let captured: string | undefined;
    const f = (url: string) => {
      captured = url;
      return Promise.resolve(
        new Response(JSON.stringify(doc), { status: 200 }),
      );
    };
    await fetchTrustedIssuers({ url: URL, fetcher: f });
    assert.equal(captured, URL);
  });
});

describe("fetchTrustedIssuers — transport errors", () => {
  it("throws non_200 on 404", async () => {
    const { doc } = makeSignedDoc();
    await assert.rejects(
      fetchTrustedIssuers({ url: URL, fetcher: jsonFetcher(doc, 404) }),
      (err: unknown) => err instanceof TrustedIssuersFetchError && err.code === "non_200",
    );
  });

  it("throws non_200 on 500", async () => {
    const { doc } = makeSignedDoc();
    await assert.rejects(
      fetchTrustedIssuers({ url: URL, fetcher: jsonFetcher(doc, 500) }),
      (err: unknown) => err instanceof TrustedIssuersFetchError && err.code === "non_200",
    );
  });

  it("throws network on fetch throw", async () => {
    await assert.rejects(
      fetchTrustedIssuers({
        url: URL,
        fetcher: async () => {
          throw new Error("ENOTFOUND");
        },
      }),
      (err: unknown) =>
        err instanceof TrustedIssuersFetchError && err.code === "network",
    );
  });

  it("throws malformed_json on invalid JSON body", async () => {
    await assert.rejects(
      fetchTrustedIssuers({
        url: URL,
        fetcher: async () => new Response("not json {", { status: 200 }),
      }),
      (err: unknown) =>
        err instanceof TrustedIssuersFetchError && err.code === "malformed_json",
    );
  });

  it("throws timeout when fetch aborts", async () => {
    await assert.rejects(
      fetchTrustedIssuers({
        url: URL,
        timeoutMs: 10,
        fetcher: async (_url, opt) => {
          return await new Promise<Response>((_resolve, reject) => {
            opt?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
          });
        },
      }),
      (err: unknown) =>
        err instanceof TrustedIssuersFetchError && err.code === "timeout",
    );
  });

  it("throws oversized_response when body exceeds 1 MB cap", async () => {
    const huge = "x".repeat(1_000_001);
    await assert.rejects(
      fetchTrustedIssuers({
        url: URL,
        fetcher: async () => new Response(huge, { status: 200 }),
      }),
      (err: unknown) =>
        err instanceof TrustedIssuersFetchError &&
        err.code === "oversized_response",
    );
  });

  it("throws network when no fetcher available and no global fetch", async () => {
    const originalFetch = globalThis.fetch;
    delete (globalThis as { fetch?: unknown }).fetch;
    try {
      await assert.rejects(
        fetchTrustedIssuers({ url: URL }),
        (err: unknown) =>
          err instanceof TrustedIssuersFetchError && err.code === "network",
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("rejects empty url with network code", async () => {
    await assert.rejects(
      fetchTrustedIssuers({ url: "" }),
      (err: unknown) =>
        err instanceof TrustedIssuersFetchError && err.code === "network",
    );
  });
});

describe("fetchTrustedIssuers — schema errors", () => {
  it("throws TrustedIssuersSchemaError on structurally invalid response", async () => {
    await assert.rejects(
      fetchTrustedIssuers({
        url: URL,
        fetcher: jsonFetcher({ kind: "wrong" }),
      }),
      (err: unknown) =>
        err instanceof TrustedIssuersSchemaError &&
        /kind/.test(err.reason),
    );
  });

  it("throws TrustedIssuersSchemaError on null body", async () => {
    await assert.rejects(
      fetchTrustedIssuers({
        url: URL,
        fetcher: async () => new Response("null", { status: 200 }),
      }),
      (err: unknown) => err instanceof TrustedIssuersSchemaError,
    );
  });
});
