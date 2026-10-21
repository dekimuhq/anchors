import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { generateKeyPairSync, createPublicKey } from "node:crypto";
import type { AddressInfo } from "node:net";
import { resolveDidWebKey, DidWebResolveError, didWebToUrl } from "../src/index.ts";

let server: Server;
let port = 0;
let docHandler: (req: { url?: string | undefined }) => { status: number; body: string };

before(async () => {
  server = createServer((req, res) => {
    const r = docHandler(req);
    res.writeHead(r.status, { "content-type": "application/json" });
    res.end(r.body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  port = (server.address() as AddressInfo).port;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("resolveDidWebKey (integration)", () => {
  it("end-to-end: real Ed25519 key roundtrip via local HTTP", async () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const spki = publicKey.export({ format: "der", type: "spki" });
    const b64 = Buffer.from(spki).toString("base64");
    const iss_key = "ed25519:" + Buffer.from(
      // extract raw 32-byte Ed25519 pub bytes (DER prefix is 12 bytes)
      spki.subarray(12),
    ).toString("base64url");

    docHandler = () => ({
      status: 200,
      body: JSON.stringify({
        version: 1,
        keys: [{
          iss_key,
          public_key_der_base64: b64,
          valid_from: "2020-01-01T00:00:00Z",
          valid_until: null,
        }],
      }),
    });

    // Force the resolver to use 127.0.0.1:port via a custom fetcher that
    // rewrites the URL host. didWebToUrl always uses https://; we override
    // to http://127.0.0.1:port for the test.
    const fetcher: typeof fetch = async (input) => {
      const u = new URL(typeof input === "string" ? input : (input as URL).href);
      const local = new URL(u.pathname, `http://127.0.0.1:${port}`);
      return fetch(local);
    };

    const pub = await resolveDidWebKey({
      iss: "did:web:example.com",
      iss_key,
      fetcher,
    });

    // Bytes must round-trip identically via createPublicKey.
    const pubKey = createPublicKey({ key: Buffer.from(pub), format: "der", type: "spki" });
    const reexported = pubKey.export({ format: "der", type: "spki" });
    assert.deepEqual(new Uint8Array(reexported), new Uint8Array(spki));
  });

  it("server 500 → non_200", async () => {
    docHandler = () => ({ status: 500, body: "" });
    const fetcher: typeof fetch = async (input) => {
      const u = new URL(typeof input === "string" ? input : (input as URL).href);
      return fetch(new URL(u.pathname, `http://127.0.0.1:${port}`));
    };
    await assert.rejects(
      resolveDidWebKey({ iss: "did:web:example.com", iss_key: "ed25519:x", fetcher }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "non_200",
    );
  });

  it("didWebToUrl maps to the expected /.well-known path", () => {
    assert.equal(
      didWebToUrl("did:web:example.com").pathname,
      "/.well-known/dekimu-keys.json",
    );
  });
});
