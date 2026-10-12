// Additional boundary and stream tests for the portable drivers. Build with
// harness/run.ts first. VH_TEST_IMPLS may select a comma-separated subset.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { canonicalize } from "../implementations/typescript/src/jcs.ts";
import { createLog } from "../implementations/typescript/src/log.ts";
import { signerFromSeed } from "../implementations/typescript/src/ed25519.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const registry = JSON.parse(readFileSync(resolve(root, "implementations.json"), "utf8")).implementations;
const names = (process.env.VH_TEST_IMPLS ?? "c,cpp,csharp,java,ruby,php,dart,scala,lua,haskell,gleam").split(",");
const seed = "42".repeat(32);
const key = signerFromSeed(seed).multikey;

// Reproducible coverage across binary64 exponents and mantissas, with the
// reference's native ECMAScript serialization as the independent oracle.
const numbers = [Number.MIN_VALUE, Number.MAX_VALUE, -0, 1e-6, 1e-7, 1e20, 1e21];
let bits = 0x123456789abcdef0n;
const buffer = Buffer.alloc(8);
for (let i = 0; i < 512; i++) {
  bits ^= bits << 13n; bits ^= bits >> 7n; bits ^= bits << 17n;
  bits = BigInt.asUintN(64, bits);
  buffer.writeBigUInt64LE(bits);
  const n = buffer.readDoubleLE();
  if (Number.isFinite(n)) numbers.push(n);
}

for (const name of names) {
  const impl = registry.find((i: any) => i.name === name);
  assert.ok(impl, `missing implementation ${name}`);
  const { PATH_PREPEND = [], ...extra } = impl.env ?? {};
  const env = { ...process.env, ...extra, PATH: [...PATH_PREPEND.map((p: string) => p.replace(/^~/, process.env.HOME ?? "~")), process.env.PATH].join(":") };
  function run(lines: string[]) {
    const result = spawnSync(impl.command[0], impl.command.slice(1), {
      cwd: resolve(root, impl.cwd), env, input: lines.join("\n"), encoding: "utf8", timeout: 60_000, maxBuffer: 8 * 1024 * 1024,
    });
    assert.equal(result.status, 0, `${result.error ?? ""}\n${result.stderr}`);
    const responses = result.stdout.trimEnd().split("\n").map((l: string) => JSON.parse(l));
    assert.equal(responses.length, lines.length, "one response per request, including unterminated final line");
    return responses;
  }
  test(`${name}: binary64 and Unicode canonicalization`, () => {
    const inputs = [JSON.stringify(numbers), '{"wide":184467440737095516160000,"rounded":123456789012345678}',
      JSON.stringify({ "😀": "astral", "\uffff": "BMP", "\r": "control", "a": "\u0000\u2028\u2029\n\\\"" }),
      '{"duplicate":1,"duplicate":2}', 'null', '-0'];
    const responses = run(inputs.map((text, id) => JSON.stringify({ id, op: "jcs", input: { text } })));
    responses.forEach((r: any, i: number) => {
      assert.equal(r.ok, true, r.error);
      assert.equal(r.result.output, canonicalize(JSON.parse(inputs[i])));
    });
  });
  if (["c", "typescript", "python"].includes(name)) {
    test(`${name}: NUL member names never collapse into prefix keys`, () => {
      const inputs = [
        '{"a\\u0000x":1,"a":2}', '{"a":2,"a\\u0000x":1}',
        '{"\\u0000":1,"":2}', '{"a\\u0000x":1,"a\\u0000y":2}',
        '[{"nested":{"a\\u0000x" \t:1}}]',
        '{"a\\u0000x":1,"a\\u0000x":2}',
      ];
      const expected = [
        '{"a":2,"a\\u0000x":1}', '{"a":2,"a\\u0000x":1}',
        '{"":2,"\\u0000":1}', '{"a\\u0000x":1,"a\\u0000y":2}',
        '[{"nested":{"a\\u0000x":1}}]', '{"a\\u0000x":2}',
      ];
      run(inputs.map((text, id) => JSON.stringify({ id, op: "jcs", input: { text } })))
        .forEach((r: any, i: number) => {
          if (name === "c") assert.deepEqual(r, { id: i, ok: false, error: "invalid-json" });
          else assert.deepEqual(r, { id: i, ok: true, result: { output: expected[i] } });
        });
    });
    test(`${name}: NUL values and literal backslash names survive round trips`, () => {
      const text = '{"a\\\\u0000x":"a\\u0000x","nested":["\\u0000",{"value":"\\u0000:"}]}';
      const request = (text: string) => JSON.stringify({ id: "roundtrip", op: "jcs", input: { text } });
      const [first] = run([request(text)]);
      assert.deepEqual(first, { id: "roundtrip", ok: true, result: { output: text } });
      assert.deepEqual(run([request(first.result.output)])[0], first);
    });
    test(`${name}: creation and resolution enforce the member-name policy`, () => {
      const versionTime = "2026-01-01T00:00:00Z";
      const input = { state: { id: "test:{SCID}", "a\0x": 1, a: 2 },
        parameters: { updateKeys: [key] }, versionTime, signers: [seed] };
      const reference = createLog(input);
      const requests = [
        { id: "create", op: "create", input },
        { id: "resolve", op: "resolve", input: { log: reference.log, now: versionTime } },
        { id: "recovery", op: "jcs", input: { text: '{"a":2}' } },
      ];
      const [created, resolved, recovered] = run(requests.map(r => JSON.stringify(r)));
      if (name === "c") {
        assert.deepEqual(created, { id: null, ok: false, error: "invalid-request" });
        assert.equal(resolved.ok, true);
        assert.equal(resolved.result.valid, false);
        assert.equal(resolved.result.error.code, "invalid-log");
      } else {
        assert.equal(created.ok, true, created.error);
        assert.deepEqual(JSON.parse(created.result.log), JSON.parse(reference.log));
        assert.equal(resolved.result.valid, true, JSON.stringify(resolved));
        assert.deepEqual(resolved.result.state, JSON.parse(reference.log).state);
      }
      assert.deepEqual(recovered, { id: "recovery", ok: true, result: { output: '{"a":2}' } });
      const valueInput = { ...input, state: { id: "test:{SCID}", value: "a\0x" } };
      const [valueCreated] = run([JSON.stringify({ id: 1, op: "create", input: valueInput })]);
      assert.equal(valueCreated.ok, true, valueCreated.error);
      assert.deepEqual(JSON.parse(valueCreated.result.log), JSON.parse(createLog(valueInput).log));
      const [valueResolved] = run([JSON.stringify({ id: 2, op: "resolve",
        input: { log: valueCreated.result.log, now: versionTime } })]);
      assert.equal(valueResolved.result.valid, true, JSON.stringify(valueResolved));
      assert.equal(valueResolved.result.state.value, "a\0x");
    });
  }
  test(`${name}: recovers from malformed requests and respects LF framing`, () => {
    const responses = run(['{', JSON.stringify({ id: 2, op: "unknown", input: {} }),
      JSON.stringify({ id: "last", op: "jcs", input: { text: '"line\u2028paragraph\u2029"' } })]);
    assert.equal(responses[0].ok, false);
    assert.equal(responses[1].ok, false);
    assert.deepEqual(responses[2], { id: "last", ok: true, result: { output: '"line\u2028paragraph\u2029"' } });
  });
  if (["dart", "scala", "lua", "haskell", "gleam"].includes(name)) {
    test(`${name}: rejects unsafe JSON and preserves LF framing and false IDs`, () => {
      const invalid = ['1e400', '"\\ud800"', '{"\\udfff":1}', '[1,]', '{"x":1} trailing'];
      const requests = invalid.map((text, id) => JSON.stringify({ id, op: "jcs", input: { text } }));
      requests.push('{"id":false,\r"op":"jcs","input":{"text":"true"}}');
      const responses = run(requests);
      responses.slice(0, invalid.length).forEach((r: any) => assert.equal(r.ok, false));
      assert.deepEqual(responses.at(-1), { id: false, ok: true, result: { output: "true" } });
    });
  }
  test(`${name}: resolves both ends of the supported calendar`, () => {
    const times = ["0000-02-29T00:00:00Z", "9999-12-31T23:59:59Z"];
    const requests = times.map((versionTime, id) => {
      const { log } = createLog({ state: { id: "test:{SCID}" }, parameters: { updateKeys: [key] }, versionTime, signers: [seed] });
      return JSON.stringify({ id, op: "resolve", input: { log, now: versionTime } });
    });
    run(requests).forEach((r: any) => { assert.equal(r.ok, true, r.error); assert.equal(r.result.valid, true, JSON.stringify(r.result.error)); });
  });
}
