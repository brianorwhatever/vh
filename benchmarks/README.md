# Driver benchmarks

Run all implementations from the repository root, using the same toolchains
listed in the main README:

```sh
node benchmarks/run.mjs
node site/build.mjs
```

The first command builds each registered implementation, measures it, and writes
`benchmarks/latest.json`. The second validates that every language has complete
results, renders the tables, and copies the data to `site/benchmarks.json` for
download. Neither command publishes anything. The Pages workflow publishes the
committed snapshot after merge; it does not rerun timings on shared CI hardware.

For a quick local comparison without replacing the site's full snapshot:

```sh
node benchmarks/run.mjs --impl rust --impl forth --output /tmp/comparison.json
node benchmarks/run.mjs --impl typescript --rounds 2 --samples 10 --warmup-ms 100 --output /tmp/smoke.json
```

`--skip-build` uses existing binaries. The default always builds first. A subset
run requires an explicit output path. A build failure, wrong answer, driver exit,
or timed-out request fails the run; output is replaced atomically only after all
selected implementations finish. There is no fallback to fabricated or stale
measurements. An existing snapshot is preserved if a new run fails.

## Workloads

All inputs and expected answers come from the shared conformance vectors:

- **Resolve · 2 entries:** the `minimal` generation scenario, with one update and
  no witnesses.
- **Resolve · 4 + witnesses:** the `witnessed` generation scenario, including its
  witness file and four entries.
- **Create · 1 entry:** the `minimal` scenario's genesis operation, including
  canonicalization, SCID/entry hashes, and one signature.
- **Sign · proof:** the first `sign` primitive vector, including proof
  configuration, canonicalization, two hashes, and an Ed25519 signature.

Every response is validated against those fixtures, outside the timed interval.
The report records each input's serialized byte length and SHA-256 hash.

## Measurement

Each implementation runs in its own persistent JSON Lines process. Only one
driver is active at a time, in registry order; only one request is in flight.
After an initial validated request starts the process, each workload warms up
for at least 1 second and 20 requests. Measurements then run for five rounds of
40 requests per workload (200 samples). Workload order rotates between rounds.
A fixed warmup does not guarantee that every JIT has reached steady state.

The monotonic timer starts immediately before writing the pre-serialized request
to the child's stdin, and stops after the matching response has arrived and been
parsed. It includes pipe communication, OS scheduling, the driver's JSON parsing
and serialization, cryptography, and the harness's response parsing. It excludes
builds, process startup, request serialization, and correctness assertions.
These are driver round-trip measurements, not isolated library benchmarks.

In particular, the Swift interop driver uses its deterministic signing path;
the public Swift library signs with swift-crypto. Its signing benchmark should
not be read as the performance of the library's signing API. The other drivers
also differ in runtime, allocator and crypto dependencies.

The median is the middle sample (the mean of the two central samples for an
even count). p95 uses nearest rank: sorted sample `ceil(0.95 * n)`. All individual
latencies are retained, grouped by round, so readers can inspect outliers and
drift. The site sorts by median and uses a linear bar scale within each workload.
The p95 is descriptive; this is not a confidence interval or significance test.

The report records UTC timestamps, CPU model, logical CPU count, memory, OS/kernel,
architecture, Node version, per-implementation runtime/compiler versions, driver
and build commands, the implementation commit/tree, and a SHA-256 fingerprint of
the benchmark runner files. Source changes under implementations, the driver
registry, or vectors mark a report dirty; the website rejects dirty snapshots.
The recorded compiler/runtime version commands are in `run.mjs`. System crypto
library versions and all transitive dependencies are not separately enumerated.

Run on an otherwise idle machine, without parallel builds or tests. Repeated
fixtures favor warm caches. CPU scheduling, thermals, background load, GC and
JIT behavior introduce noise; the implementation order is not randomized.
Compare repeated runs on the same hardware before drawing conclusions from small
differences. These figures do not measure cold starts, large histories, memory,
network fetching, concurrency, or application throughput.

## Checks

```sh
node --test benchmarks/benchmark.test.mjs
node site/build.mjs
```

CI checks protocol framing/failure handling, fixture correctness, statistics and
snapshot completeness. It does not gate on timing thresholds or update the
published measurements automatically. To refresh the site, run the benchmarks
locally and commit `benchmarks/latest.json` with the resulting machine context.
