# 02-tampered-body

Valid claim mutated post-signing (`body.summary` changed from `vector 01J0TEST00000000000000A002` to `TAMPERED`). Signature was computed over the original body, so Ed25519 verification fails. The anchor would otherwise verify the id for this date — the verifier MUST return `tampered` / `signature_invalid` without ever consulting the anchor.
