import { summarize } from '../benchmarks/stats.mjs';

const esc = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const ms = value => value.toLocaleString('en-US', { minimumFractionDigits: 3, maximumFractionDigits: 3 });

export function benchmarkSection(report, languages, repo) {
  if (report.schemaVersion !== 1 || report.sourceDirty || !/^[a-f0-9]{40}$/.test(report.sourceCommit)) throw new Error('Invalid benchmark provenance');
  const { rounds, samplesPerRound, warmupMs } = report.method;
  if (![rounds, samplesPerRound, warmupMs].every(n => Number.isSafeInteger(n) && n > 0)) throw new Error('Invalid benchmark methodology');
  const expected = new Set(languages.map(l => l.id));
  const actual = report.implementations.map(i => i.name);
  if (actual.length !== expected.size || new Set(actual).size !== actual.length || actual.some(n => !expected.has(n))) throw new Error('Benchmark snapshot must contain every implementation exactly once');
  const ids = report.workloads.map(w => w.id);
  if (!ids.length || new Set(ids).size !== ids.length || ids.some(id => !/^[a-z-]+$/.test(id))) throw new Error('Invalid benchmark workload IDs');
  const names = Object.fromEntries(languages.map(l => [l.id, l.name]));
  const panels = report.workloads.map(workload => {
    const rows = report.implementations.map(impl => {
      const batches = impl.results[workload.id]?.roundsMs;
      if (!batches || batches.length !== rounds || batches.some(r => r.length !== samplesPerRound)) throw new Error(`Incomplete benchmark samples: ${impl.name}/${workload.id}`);
      return { name: names[impl.name], ...summarize(batches.flat()) };
    }).sort((a, b) => a.medianMs - b.medianMs);
    const max = Math.max(...rows.map(r => r.medianMs));
    return `<div data-benchmark-panel="${workload.id}">
      <h3>${esc(workload.title)}</h3>
      <p class="bench-description">${esc(workload.description)} Input: ${workload.inputBytes.toLocaleString('en-US')} bytes of JSON.</p>
      <table class="bench-table">
        <caption>Warm request latency in milliseconds. Lower is faster. Bars share a linear scale within this workload; sorted by median.</caption>
        <thead><tr><th scope="col">Implementation</th><th scope="col">Median <span>(ms)</span></th><th scope="col">p95 <span>(ms)</span></th></tr></thead>
        <tbody>${rows.map(r => `<tr><th scope="row">${esc(r.name)}<span class="bench-track" aria-hidden="true"><span style="width:${(100 * r.medianMs / max).toFixed(3)}%"></span></span></th><td>${ms(r.medianMs)}</td><td>${ms(r.p95Ms)}</td></tr>`).join('')}</tbody>
      </table>
    </div>`;
  }).join('\n');
  const machine = report.machine;
  const measuredDate = new Date(report.completedAt).toISOString().slice(0, 10);
  return `<section class="benchmarks" aria-labelledby="benchmarks">
    <h2 id="benchmarks">Same work, different timings</h2>
    <p class="section-lede">Measured driver requests on one machine. Choose a workload to compare the implementations.</p>
    <div class="bench-controls"><label for="benchmark-workload">Workload</label><select id="benchmark-workload">${report.workloads.map(w => `<option value="${w.id}">${esc(w.title)}</option>`).join('')}</select></div>
    <div class="bench-grid"><div class="bench-results">${panels}</div>
      <aside class="bench-method" aria-labelledby="benchmark-method">
        <h3 id="benchmark-method">What these numbers measure</h3>
        <p>One request at a time through the same JSON Lines protocol. Timings include inter-process communication, JSON parsing and the driver's work. Builds, process startup, request serialization and correctness assertions are outside the clock.</p>
        <p>${rounds * samplesPerRound} measured requests per implementation and workload, in ${rounds} rounds of ${samplesPerRound}, after at least ${warmupMs / 1000} seconds and ${report.method.minimumWarmupRequests} warmup requests. Every answer is checked. Median is the middle latency; p95 is the latency at or below which 95% of requests finished.</p>
        <p>These small, repeated fixtures are a snapshot of the drivers and their crypto libraries, not a general language ranking. Runtime compilation, garbage collection and other work on the machine can affect the results. They do not measure cold starts, large histories or concurrent service throughput.</p>
        <p>Swift’s interop driver uses deterministic signing; its library signs with swift-crypto. The signing figures here describe that driver path.</p>
        <dl class="bench-machine"><dt>Measured</dt><dd>${measuredDate} (UTC)</dd><dt>Machine</dt><dd>${esc(machine.cpu)} · ${machine.logicalCpus} logical CPUs · ${machine.memoryGiB} GiB</dd><dt>System</dt><dd>${esc(machine.platform)} ${esc(machine.release)} · ${esc(machine.arch)}</dd><dt>Harness</dt><dd>Node ${esc(machine.node)}</dd><dt>Implementation revision</dt><dd><a href="${repo}/commit/${report.sourceCommit}">${report.sourceCommit.slice(0, 7)}</a></dd></dl>
        <details><summary>Runtime and toolchain versions</summary><ul class="bench-versions">${report.implementations.map(i => `<li><b>${esc(names[i.name])}</b><pre>${esc(i.runtime)}</pre></li>`).join('')}</ul></details>
        <p><a href="benchmarks.json" download>Download samples and environment (JSON)</a><br><a href="${repo}/blob/main/benchmarks/README.md">Methodology and reproduction</a></p>
        <pre class="bench-command"><code>node benchmarks/run.mjs
node site/build.mjs</code></pre>
      </aside>
    </div>
  </section>`;
}
