import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Driver } from './driver.mjs';
import { workloads } from './workloads.mjs';
import { summarize } from './stats.mjs';
import { benchmarkSection } from '../site/benchmarks.mjs';

const root = new URL('../', import.meta.url);
const fake = source => new Driver([process.execPath, '-e', source], {}, 500);

test('median and nearest-rank p95 use individual request samples', () => {
  assert.deepEqual(summarize([4, 1, 3, 2]), { samples: 4, medianMs: 2.5, p95Ms: 4 });
  assert.equal(summarize(Array.from({ length: 100 }, (_, i) => i + 1)).p95Ms, 95);
  for (const values of [[], [NaN], [0], [-1], [Infinity]]) assert.throws(() => summarize(values));
});

test('all benchmark fixtures produce and validate correct answers', async () => {
  const driver = new Driver([process.execPath, 'src/driver.ts'], { cwd: fileURLToPath(new URL('implementations/typescript/', root)) });
  try {
    for (const c of workloads(root)) {
      const response = await driver.call(c.op, c.input);
      c.check(response.result);
      assert(response.ms > 0);
      assert.throws(() => c.check({ valid: false, proof: {}, log: '{}' }));
    }
  } finally { await driver.close(); }
});

test('driver keeps fragmented UTF-8 and Unicode separators in one response', async () => {
  const driver = fake(`process.stdin.once('data', b => {
    const r=JSON.parse(b); const s=Buffer.from(JSON.stringify({id:r.id,ok:true,result:'😀\\u2028\\u2029'})+'\\n');
    for(let i=0;i<s.length;i++) setTimeout(()=>process.stdout.write(s.subarray(i,i+1)),i);
  });`);
  try { assert.equal((await driver.call('test', {})).result, '😀\u2028\u2029'); }
  finally { await driver.close(); }
});

test('driver rejects errors, wrong IDs, malformed output, crashes and timeouts', async () => {
  const responders = [
    `process.stdin.once('data', b=>process.stdout.write(JSON.stringify({id:JSON.parse(b).id,ok:false,error:'bad'})+'\\n'));`,
    `process.stdin.once('data', ()=>process.stdout.write('{"id":999,"ok":true}\\n'));`,
    `process.stdin.once('data', ()=>process.stdout.write('not json\\n'));`,
    `process.stdin.once('data', ()=>process.exit(1));`,
    `process.stdin.resume();`,
  ];
  for (const source of responders) {
    const driver = fake(source);
    try { await assert.rejects(driver.call('test', {})); }
    finally { await driver.close(); }
  }
});

test('site refuses missing implementations, incomplete samples and non-finite timings', () => {
  const report = JSON.parse(readFileSync(new URL('latest.json', import.meta.url)));
  const langs = report.implementations.map(i => ({ id: i.name, name: i.name }));
  const render = data => benchmarkSection(data, langs, 'https://example.com/vh');
  assert.match(render(report), /Download samples/);
  for (const mutate of [
    r => r.implementations.pop(),
    r => r.implementations[0].results[r.workloads[0].id].roundsMs.pop(),
    r => { r.implementations[0].results[r.workloads[0].id].roundsMs[0][0] = NaN; },
    r => { r.sourceDirty = true; },
  ]) {
    const copy = structuredClone(report); mutate(copy); assert.throws(() => render(copy));
  }
});
