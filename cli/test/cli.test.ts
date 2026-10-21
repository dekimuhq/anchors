/**
 * CLI surface tests — `runCli` with injected file reads (no process spawn).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { runCli } from "../src/cli.ts";
import { mintAsrReceipt, fakeReadFile, KP } from "./_helpers.ts";
import { base64UrlEncode } from "@dekimuhq/anchors-envelope";

test("verify: valid receipt file -> exit 0, PASS line", async () => {
  const receipt = await mintAsrReceipt();
  const deps = { readFile: fakeReadFile({ "r.json": JSON.stringify(receipt) }) };
  const r = await runCli(["verify", "r.json"], deps);
  assert.equal(r.exitCode, 0);
  assert.match(r.stdout, /PASS/);
  assert.match(r.stdout, /ASR/);
  assert.match(r.stdout, /self-certifying/);
});

test("verify: tampered receipt -> exit 1, FAIL line", async () => {
  const receipt = await mintAsrReceipt();
  const tampered = { ...receipt, subject: "sha256:" + "0".repeat(64) };
  const deps = { readFile: fakeReadFile({ "r.json": JSON.stringify(tampered) }) };
  const r = await runCli(["verify", "r.json"], deps);
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /FAIL/);
});

test("verify: array of receipts -> per-receipt lines", async () => {
  const receipt = await mintAsrReceipt();
  const deps = { readFile: fakeReadFile({ "r.json": JSON.stringify([receipt, receipt]) }) };
  const r = await runCli(["verify", "r.json"], deps);
  assert.equal(r.exitCode, 0);
  assert.equal((r.stdout.match(/PASS/g) ?? []).length, 2);
  assert.match(r.stdout, /r\.json\[0\]/);
});

test("verify: --json emits structured outcome", async () => {
  const receipt = await mintAsrReceipt();
  const deps = { readFile: fakeReadFile({ "r.json": JSON.stringify(receipt) }) };
  const r = await runCli(["verify", "r.json", "--json"], deps);
  assert.equal(r.exitCode, 0);
  const parsed = JSON.parse(r.stdout);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.mode, "self-certifying");
  assert.equal(parsed.files[0].outcomes[0].family, "ASR");
});

test("verify: --trusted-keys allowlists the issuer", async () => {
  const receipt = await mintAsrReceipt();
  const fingerprint = `ed25519:${base64UrlEncode(KP.publicKey)}`;
  const deps = {
    readFile: fakeReadFile({
      "r.json": JSON.stringify(receipt),
      "keys.json": JSON.stringify([fingerprint]),
    }),
  };
  const r = await runCli(["verify", "r.json", "--trusted-keys", "keys.json"], deps);
  assert.equal(r.exitCode, 0);
  assert.match(r.stdout, /trusted-keys/);
});

test("verify: --trusted-keys rejects an unlisted issuer", async () => {
  const receipt = await mintAsrReceipt();
  const other = `ed25519:${base64UrlEncode(new Uint8Array(32))}`;
  const deps = {
    readFile: fakeReadFile({
      "r.json": JSON.stringify(receipt),
      "keys.json": JSON.stringify([other]),
    }),
  };
  const r = await runCli(["verify", "r.json", "--trusted-keys", "keys.json"], deps);
  assert.equal(r.exitCode, 1);
});

test("verify: missing file -> exit 2", async () => {
  const deps = { readFile: fakeReadFile({}) };
  const r = await runCli(["verify", "nope.json"], deps);
  assert.equal(r.exitCode, 2);
  assert.match(r.stderr, /cannot read/);
});

test("no command -> exit 2, usage", async () => {
  const r = await runCli([], { readFile: fakeReadFile({}) });
  assert.equal(r.exitCode, 2);
  assert.match(r.stderr, /no command/);
});

test("unknown command -> exit 2", async () => {
  const r = await runCli(["frobnicate"], { readFile: fakeReadFile({}) });
  assert.equal(r.exitCode, 2);
  assert.match(r.stderr, /unknown command/);
});

test("--help -> exit 0, usage on stdout", async () => {
  const r = await runCli(["--help"], { readFile: fakeReadFile({}) });
  assert.equal(r.exitCode, 0);
  assert.match(r.stdout, /Usage:/);
});

test("verify with no files -> exit 2", async () => {
  const r = await runCli(["verify"], { readFile: fakeReadFile({}) });
  assert.equal(r.exitCode, 2);
  assert.match(r.stderr, /no input files/);
});
