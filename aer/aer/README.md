# @dekimuhq/aer

Verifier for **Anchored Evaluation Receipts (AER)** — the 7th member of the
[Anchored Receipts](https://github.com/dekimuhq/anchors) protocol
family.

AER anchors cryptographic evidence of AI Act conformity assessments (Art. 43)
and transparency obligations (Art. 50).

## Usage

```ts
import { verifyReceipt } from "@dekimuhq/aer";

const result = await verifyReceipt(receipt, {
  resolveKey: async (iss_key) => publicKeyBytes,
});

if (result.signature_valid) {
  // receipt is authentic
}
```

## License

Apache-2.0
