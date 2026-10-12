// Independent expected outcomes; these vectors never consult a VH-Log oracle.
// Build selected drivers first: node harness/run.ts --suite primitives
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const registry = JSON.parse(readFileSync(new URL('implementations.json', root), 'utf8')).implementations;
const cases = JSON.parse(readFileSync(new URL('vectors/ed25519/boundaries.json', root), 'utf8'));
const names = process.env.VH_TEST_IMPLS?.split(',') ?? registry.map((i: any) => i.name);
for (const name of names) {
  test(`${name}: independent Ed25519 proof and resolver boundaries`, () => {
    const impl = registry.find((i: any) => i.name === name);
    assert.ok(impl, name);
    const { PATH_PREPEND = [], ...extra } = impl.env ?? {};
    const env = { ...process.env, ...extra, PATH: [...PATH_PREPEND.map((p: string) => p.replace(/^~/, process.env.HOME ?? '~')), process.env.PATH].join(':') };
    const result = spawnSync(impl.command[0], impl.command.slice(1), {
      cwd: new URL(impl.cwd + '/', root), env,
      input: cases.map((v: any, id: number) => JSON.stringify({ id, op: v.op, input: v.input })).join('\n')+'\n',
      encoding: 'utf8', timeout: 120_000, maxBuffer: 16*1024*1024,
    });
    assert.equal(result.status, 0, `${result.error ?? ''}\n${result.stderr}`);
    const responses = result.stdout.trim().split('\n').map(l => JSON.parse(l));
    assert.equal(responses.length, cases.length);
    const failures: string[] = [];
    responses.forEach((r: any, i: number) => {
      const v = cases[i];
      if (r.id !== i || r.ok !== true || r.result.valid !== v.expected.valid ||
          ('error' in v.expected && (r.result.error?.code ?? null) !== v.expected.error) ||
          (v.expected.firstInvalidVersion && r.result.firstInvalidVersion !== v.expected.firstInvalidVersion)) {
        failures.push(`${v.op} ${v.name}: expected ${JSON.stringify(v.expected)}, actual ${JSON.stringify(r)}`);
      }
    });
    assert.deepEqual(failures, []);
    console.log(`${name}: ${cases.filter((v: any) => v.op === 'verify').length} proof-library driver cases; ${cases.filter((v: any) => v.op === 'resolve').length} resolver cases passed`);
  });
}
