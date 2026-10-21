# @dekimuhq/<member>-issuer-kit

Issuer kit for **Anchored <Noun> Receipts** (<MEMBER>) v1. Node-only — generates Ed25519 keypairs and mints signed envelopes.

Part of the [Anchored Receipts](https://github.com/dekimuhq/anchors) family. See the [v1 design spec](TODO: link to spec file) for protocol details.

## Install

```bash
npm install @dekimuhq/<member>-issuer-kit
```

## Quickstart

```ts
import { generateKeypair, mint<MEMBER> } from "@dekimuhq/<member>-issuer-kit";

const keypair = await generateKeypair();

const receipt = await mint<MEMBER>({
  iss: "did:web:example.com:<member>:issuer",
  privateKey: keypair.privateKey,
  body: {
    // member-specific body fields per spec §4.2
  },
  profile: "<member>.<profile>.<version>",
  envelope_v: 2, // default
  // optional TSA opt-in:
  // tsa: { url: "https://freetsa.org/tsr" },
  // optional Status List index:
  // getNextStatusIndex: async (bucket) => myCounter.next(bucket),
});
```

See `quickstart/` for runnable examples.

## What this issuer kit does NOT do

- Anchor-log inclusion is performed by the `verify.dekimu.com` worker, not the issuer kit. Issuer kit returns a signed envelope with `anchor: null`; the worker fills in `anchor.*` and emits the final receipt.
- Status List 2021 publishing is done by the worker. Issuer kit only allocates `statusListIndex` via the caller-provided `getNextStatusIndex` callback.
- Caller is responsible for persisting `statusListIndex` counters (file, Redis, Postgres — see `docs/persistence.md`).

## License

Apache-2.0
