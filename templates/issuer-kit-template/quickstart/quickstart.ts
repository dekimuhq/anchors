// @dekimuhq/<member>-issuer-kit — quickstart
//
// Run with: node --experimental-strip-types quickstart/quickstart.ts

import { generateKeypair, mint<MEMBER> } from "../src/index.ts";

const kp = await generateKeypair();

const { receipt } = await mint<MEMBER>({
  iss: "did:web:example.com:<member>:issuer",
  iss_key: kp.iss_key,
  privateKey: kp.privateKey,
  subject: "sha256:" + "0".repeat(64),
  body: {
    // member-specific body per spec §4.2
  },
  profile: "<member>.quickstart.v1",
});

console.log(JSON.stringify(receipt, null, 2));
