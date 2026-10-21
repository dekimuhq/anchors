import { test } from "node:test";
import assert from "node:assert/strict";
import { SignedSpanExporter } from "../src/exporter.ts";
import { otelSpan } from "./_helpers/otel-fixtures.ts";

test("export batches a trace, calls mint with a well-formed body, hands envelope to sink", async () => {
  const minted: unknown[] = [];
  const exporter = new SignedSpanExporter({
    mint: async (body, detail) => {
      assert.equal(body.profile, "agent.trace");
      assert.ok(Array.isArray(body.spans) && body.spans.length === 1);
      assert.ok(detail[body.spans[0].span_id]);
      return { fake_envelope: true, trace_id: body.trace_id };
    },
    sink: (env) => { minted.push(env); },
    request_id_commit: "sha256:" + "a".repeat(64),
    outcome: () => "ok",
  });
  const done = await new Promise<{ code: number }>((res) => exporter.export([otelSpan()] as never[], res));
  assert.equal(done.code, 0);
  assert.equal(minted.length, 1);
});

test("export reports code 1 when mint throws", async () => {
  const exporter = new SignedSpanExporter({
    mint: async () => { throw new Error("mint blew up"); },
    sink: () => {},
    request_id_commit: "sha256:" + "b".repeat(64),
  });
  const done = await new Promise<{ code: number; error?: Error }>((res) =>
    exporter.export([otelSpan()] as never[], res),
  );
  assert.equal(done.code, 1);
  assert.ok(done.error instanceof Error);
});
