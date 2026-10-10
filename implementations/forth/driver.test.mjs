import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const cwd = new URL('.', import.meta.url);
function exchange(requests) {
  const input = requests.map((r, id) => typeof r === 'string' ? r : JSON.stringify({ id, ...r })).join('\n') + '\n';
  const proc = spawnSync('sh', ['run.sh'], { cwd, input, encoding: 'utf8', timeout: 30_000 });
  assert.equal(proc.status, 0, proc.stderr);
  const responses = proc.stdout.trim().split('\n').map(JSON.parse);
  assert.equal(responses.length, requests.length, proc.stdout);
  return responses;
}
const vectors = name => JSON.parse(readFileSync(new URL(`../../vectors/resolution/${name}.json`, cwd))).cases;
const caseInput = c => c.input;

test('malformed requests do not terminate or contaminate the next request', () => {
  const requests = [
    '{',
    { op: 'unknown', input: {} },
    { op: 'multikey', input: { seed: 'not-a-seed' } },
    { op: 'create', input: { parameters: 17 } },
    { op: 'jcs', input: { text: '{"bad":"\\ud800"}' } },
    { op: 'hash', input: { data: 'abc' } },
  ];
  const responses = exchange(requests);
  for (const response of responses.slice(0, -1)) {
    assert.equal(response.ok, false);
    assert.equal(typeof response.error, 'string');
  }
  assert.equal(responses[0].id, null);
  assert.deepEqual(responses.at(-1), { id: 5, ok: true, result: { output: 'QmatYkNGZnELf8cAGdyJpUca2PyY4szai3RHyyWofNY1pY' } });
});

test('JSON Lines preserves NUL, CR, U+2028 and U+2029 inside strings', () => {
  const value = { text: '\0\r\u2028\u2029' };
  const [response] = exchange([{ op: 'jcs', input: { text: JSON.stringify(value) } }]);
  assert.equal(response.ok, true);
  assert.equal(response.result.output, JSON.stringify(value));
});

test('fork errors identify both sources and their first differing version IDs', () => {
  const input = caseInput(vectors('copies').find(c => c.name === 'fork'));
  const [{ result }] = exchange([{ op: 'resolve', input }]);
  assert.equal(result.valid, false);
  assert.equal(result.error.code, 'fork-detected');
  const primary = input.log.trim().split('\n').map(JSON.parse);
  const other = input.copies[0].log.trim().split('\n').map(JSON.parse);
  assert.deepEqual(result.error.fork, {
    version: 3,
    copies: [
      { source: 'primary', versionId: primary[2].versionId },
      { source: input.copies[0].source, versionId: other[2].versionId },
    ],
  });
});

test('an extending copy reuses the trusted prefix and validates only its suffix', () => {
  const input = structuredClone(caseInput(vectors('copies').find(c => c.name === 'primary-behind')));
  const original = input.log.trim().split('\n').map(JSON.parse);
  const copy = input.copies[0].log.trim().split('\n').map(JSON.parse);
  // The final prefix versionId still matches, so this prefix must not replace
  // the verified history or be revalidated. Selection must use trusted IDs.
  copy[0].state = { tampered: true };
  copy[0].versionId = 'untrusted-prefix';
  input.copies[0].log = copy.map(JSON.stringify).join('\n') + '\n';
  input.options = { versionId: original[0].versionId };
  const [{ result }] = exchange([{ op: 'resolve', input }]);
  assert.equal(result.valid, true);
  assert.equal(result.error, null);
  assert.deepEqual(result.state, original[0].state);
  assert.equal(result.metadata.updated, copy.at(-1).versionTime);
});

test('parameter integers outside the representable range are rejected', () => {
  const initial = caseInput(vectors('parameters').find(c => c.name === 'defaults'));
  const entry = JSON.parse(initial.log.trim());
  entry.parameters.ttl = 1e100;
  const [{ result }] = exchange([{ op: 'resolve', input: { ...initial, log: JSON.stringify(entry) + '\n' } }]);
  assert.equal(result.error.code, 'invalid-parameter');
});

test('request arena and Forth stacks survive a stream of mixed operations', () => {
  const requests = Array.from({ length: 100 }, (_, i) => ({ op: 'jcs', input: { text: JSON.stringify({ z: i, a: [null, true, '😀'] }) } }));
  for (const [i, response] of exchange(requests).entries()) {
    assert.equal(response.id, i);
    assert.equal(response.ok, true);
    assert.equal(response.result.output, JSON.stringify({ a: [null, true, '😀'], z: i }));
  }
});
