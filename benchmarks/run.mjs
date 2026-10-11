// node benchmarks/run.mjs [--impl rust --output /tmp/rust.json]
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import { performance } from 'node:perf_hooks';
import { parseArgs } from 'node:util';
import { Driver } from './driver.mjs';
import { workloads } from './workloads.mjs';
import { summarize } from './stats.mjs';

const rootUrl = new URL('../', import.meta.url);
const root = fileURLToPath(rootUrl);
const { values } = parseArgs({ options: {
  impl: { type: 'string', multiple: true }, output: { type: 'string' },
  samples: { type: 'string', default: '40' }, rounds: { type: 'string', default: '5' },
  'warmup-ms': { type: 'string', default: '1000' }, 'skip-build': { type: 'boolean', default: false },
} });
const samples = Number(values.samples), rounds = Number(values.rounds), warmupMs = Number(values['warmup-ms']);
for (const n of [samples, rounds, warmupMs]) if (!Number.isSafeInteger(n) || n <= 0) throw new Error('Sample counts, rounds and warmup-ms must be positive integers');
if (values.impl && !values.output) throw new Error('A subset run requires --output, to preserve the published snapshot');
const registry = JSON.parse(readFileSync(new URL('implementations.json', rootUrl))).implementations;
for (const name of values.impl ?? []) if (!registry.some(i => i.name === name)) throw new Error(`Unknown implementation: ${name}`);
const selected = registry.filter(i => !values.impl || values.impl.includes(i.name));
const cases = workloads(rootUrl);
const versions = {
  typescript: ['node', '--version'], rust: ['rustc', '--version'], python: ['uv', 'run', '--no-sync', 'python', '--version'],
  elixir: ['elixir', '--version'], go: ['go', 'version'], swift: ['swift', '--version'],
  kotlin: ['java', '-version'], zig: ['zig', 'version'], 'common-lisp': ['sbcl', '--version'], forth: ['gforth', '--version'],
  c: ['cc', '--version'], cpp: ['c++', '--version'], csharp: ['dotnet', '--version'],
  java: ['java', '-version'], ruby: ['ruby', '--version'], php: ['php', '--version'],
  raku: ['raku', '--version'], ocaml: ['ocamlopt', '-version'],
  ada: ['sh', '-c', 'if command -v gnatmake >/dev/null 2>&1; then exec gnatmake --version; fi; for compiler in "$HOME"/.local/share/alire/toolchains/gnat_native_*/bin/gnatmake; do if [ -x "$compiler" ]; then exec "$compiler" --version; fi; done; exit 1'],
  dart: ['dart', '--version'], haskell: ['ghc', '--version'], lua: ['lua', '-v'],
  gleam: ['gleam', '--version'], scala: ['scala-cli', 'version'],
};
function environment(impl) {
  const { PATH_PREPEND = [], ...vars } = impl.env ?? {};
  return { ...process.env, ...vars, PATH: [...PATH_PREPEND.map(p => p.replace(/^~/, os.homedir())), process.env.PATH].join(':') };
}
function command(argv, options) {
  const result = spawnSync(argv[0], argv.slice(1), { ...options, encoding: 'utf8', timeout: 600_000, maxBuffer: 10 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(`${argv.join(' ')} failed: ${result.error?.message ?? ''}\n${result.stderr?.slice(-2000) ?? ''}`);
  return (result.stdout + result.stderr).trim();
}
const sha = data => createHash('sha256').update(data).digest('hex');
const revision = command(['git', 'rev-parse', 'HEAD'], { cwd: root });
const report = {
  schemaVersion: 1, startedAt: new Date().toISOString(), sourceCommit: revision,
  sourceTree: command(['git', 'rev-parse', 'HEAD:implementations'], { cwd: root }),
  sourceDirty: command(['git', 'status', '--porcelain', '--', 'implementations', 'implementations.json', 'vectors'], { cwd: root }).length > 0,
  runnerSha256: sha(['run.mjs', 'driver.mjs', 'workloads.mjs', 'stats.mjs'].map(p => readFileSync(new URL(p, import.meta.url), 'utf8')).join('\n')),
  machine: { cpu: os.cpus()[0]?.model ?? 'unknown', logicalCpus: os.cpus().length, memoryGiB: Math.round(os.totalmem() / 1024 ** 3), platform: os.platform(), release: os.release(), arch: os.arch(), node: process.version },
  method: { samplesPerRound: samples, rounds, warmupMs, minimumWarmupRequests: 20, concurrency: 1, clock: 'performance.now', scope: 'Persistent JSON Lines driver round trip; includes IPC and response parsing, excludes builds, process startup, request serialization and result assertions.', implementationOrder: selected.map(i => i.name) },
  workloads: cases.map(({ id, title, description, op, input }) => ({ id, title, description, op, inputBytes: Buffer.byteLength(JSON.stringify(input)), inputSha256: sha(JSON.stringify(input)) })),
  implementations: [],
};
for (const impl of selected) {
  const options = { cwd: resolve(root, impl.cwd), env: environment(impl) };
  console.log(`Building ${impl.name}…`);
  if (impl.build && !values['skip-build']) command(impl.build, options);
  const runtime = command(versions[impl.name], options);
  const driver = new Driver(impl.command, options);
  const results = Object.fromEntries(cases.map(c => [c.id, { warmupRequests: 0, roundsMs: [] }]));
  try {
    for (const c of cases) {
      c.check((await driver.call(c.op, c.input)).result); // Start the process before the warmup clock.
      const start = performance.now();
      do {
        c.check((await driver.call(c.op, c.input)).result);
        results[c.id].warmupRequests++;
      } while (performance.now() - start < warmupMs || results[c.id].warmupRequests < 20);
    }
    for (let round = 0; round < rounds; round++) {
      // Rotate workload order each round to spread within-process drift.
      for (let i = 0; i < cases.length; i++) {
        const c = cases[(i + round) % cases.length];
        const times = [];
        for (let j = 0; j < samples; j++) {
          const response = await driver.call(c.op, c.input);
          c.check(response.result); // A wrong answer is never recorded as fast.
          times.push(response.ms);
        }
        results[c.id].roundsMs.push(times);
      }
    }
  } finally { await driver.close(); }
  report.implementations.push({ name: impl.name, runtime, command: impl.command, build: impl.build ?? null, results });
  console.log(impl.name, Object.fromEntries(Object.entries(results).map(([id, r]) => [id, `${summarize(r.roundsMs.flat()).medianMs.toFixed(3)} ms`])));
}
report.completedAt = new Date().toISOString();
const output = resolve(values.output ?? fileURLToPath(new URL('latest.json', import.meta.url)));
mkdirSync(dirname(output), { recursive: true });
const temporary = `${output}.${process.pid}.tmp`;
writeFileSync(temporary, JSON.stringify(report, null, 2) + '\n');
renameSync(temporary, output); // Failed/incomplete runs never replace published data.
console.log(`Wrote ${output}`);
