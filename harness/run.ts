// Interop harness: runs every registered driver against the shared vectors,
// then has every driver resolve the logs every other driver generated.
//
//   node harness/run.ts                      # all implementations, all suites
//   node harness/run.ts --impl python        # only these implementations (repeatable)
//   node harness/run.ts --suite resolution   # primitives | resolution | generation | cross | external (repeatable)
//   node harness/run.ts --list               # print every test result, not just failures
//   node harness/run.ts --verbose            # print every failure in full
//   node harness/run.ts --markdown out.md    # also write the results as Markdown (CI job summary)
//   node harness/run.ts --update-readme      # rewrite the interop matrix in README.md
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { canonicalize } from "../implementations/typescript/src/jcs.ts";
import { lines } from "../implementations/typescript/src/lines.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const VECTORS = join(ROOT, "vectors");
const TIMEOUT_MS = 30_000;

type Json = any;

interface ImplConfig {
  name: string;
  cwd: string;
  /** Run once before the driver starts; a failure is reported and the driver skipped. */
  build?: string[];
  command: string[];
  /** Extra environment variables; `PATH_PREPEND` entries are prepended to PATH. */
  env?: { PATH_PREPEND?: string[]; [name: string]: string | string[] | undefined };
}

function implEnv(impl: ImplConfig): NodeJS.ProcessEnv {
  const prepend = (impl.env?.PATH_PREPEND ?? []).map((p) => p.replace(/^~/, process.env.HOME ?? "~"));
  const { PATH_PREPEND: _, ...vars } = impl.env ?? {};
  return { ...process.env, ...(vars as Record<string, string>), PATH: [...prepend, process.env.PATH].join(":") };
}

function build(impl: ImplConfig): string | null {
  if (!impl.build) return null;
  const r = spawnSync(impl.build[0], impl.build.slice(1), {
    cwd: join(ROOT, impl.cwd),
    env: implEnv(impl),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (r.status === 0) return null;
  return `build failed (${impl.build.join(" ")}): ${r.error?.message ?? ""}\n${(r.stderr ?? "").slice(-3000)}`;
}

class Driver {
  private proc: ChildProcessWithoutNullStreams;
  private pending = new Map<number, (v: Json) => void>();
  private nextId = 1;
  private stderr = "";
  private exited: string | null = null;
  readonly impl: ImplConfig;

  constructor(impl: ImplConfig) {
    this.impl = impl;
    this.proc = spawn(impl.command[0], impl.command.slice(1), { cwd: join(ROOT, impl.cwd), env: implEnv(impl) });
    this.proc.stderr.on("data", (d) => {
      this.stderr = (this.stderr + d).slice(-4000);
    });
    this.proc.on("exit", (code) => {
      this.exited = `driver exited with code ${code}\n${this.stderr}`;
      for (const resolve of this.pending.values()) resolve({ ok: false, error: this.exited });
      this.pending.clear();
    });
    this.proc.on("error", (e) => {
      this.exited = `driver failed to start: ${e.message}`;
    });
    void (async () => {
      for await (const line of lines(this.proc.stdout)) {
        let msg: Json;
        try {
          msg = JSON.parse(line);
        } catch {
          this.stderr += `\n[harness] non-JSON stdout: ${line.slice(0, 200)}`;
          continue;
        }
        const resolve = this.pending.get(msg.id);
        if (resolve) {
          this.pending.delete(msg.id);
          resolve(msg);
        }
      }
    })();
  }

  /** Sends a request; `rawInput` (JSON text) is spliced in verbatim so number text survives. */
  call(op: string, input: Json, rawInput?: string): Promise<{ ok: boolean; result?: Json; error?: string }> {
    if (this.exited) return Promise.resolve({ ok: false, error: this.exited });
    const id = this.nextId++;
    const line = `{"id":${id},"op":${JSON.stringify(op)},"input":${rawInput ?? JSON.stringify(input)}}\n`;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve({ ok: false, error: `timed out after ${TIMEOUT_MS} ms` });
      }, TIMEOUT_MS);
      this.pending.set(id, (v) => {
        clearTimeout(timer);
        resolve(v);
      });
      this.proc.stdin.write(line);
    });
  }

  close(): void {
    this.proc.stdin.end();
  }
}

// ---------------------------------------------------------------- results

interface Result {
  impl: string;
  suite: string;
  test: string;
  /** null when the test passed. */
  problem: string | null;
  /** For the cross suite: the implementation that generated the log. */
  producer?: string;
}

const results: Result[] = [];

function record(impl: string, suite: string, test: string, problem: string | null, producer?: string) {
  results.push({ impl, suite, test, problem, ...(producer ? { producer } : {}) });
}

const same = (a: unknown, b: unknown) => {
  try {
    return canonicalize(a) === canonicalize(b);
  } catch {
    return false;
  }
};
const show = (v: unknown) => JSON.stringify(v)?.slice(0, 400);

// ---------------------------------------------------------------- suites

async function primitives(d: Driver) {
  const v = JSON.parse(readFileSync(join(VECTORS, "primitives.json"), "utf8"));
  const check = async (test: string, op: string, input: Json, pick: (r: Json) => unknown, want: unknown, raw?: string) => {
    const res = await d.call(op, input, raw);
    if (!res.ok) return record(d.impl.name, "primitives", test, `driver error: ${res.error}`);
    const got = pick(res.result);
    record(d.impl.name, "primitives", test, same(got, want) ? null : `expected ${show(want)}\n     got ${show(got)}`);
  };
  for (const [i, c] of v.jcs.entries()) {
    await check(`jcs[${i}]`, "jcs", null, (r) => r.output, c.output, JSON.stringify({ text: c.text }));
  }
  for (const [i, c] of v.hash.entries()) await check(`hash[${i}]`, "hash", { data: c.data }, (r) => r.output, c.output);
  for (const [i, c] of v.multikey.entries()) await check(`multikey[${i}]`, "multikey", { seed: c.seed }, (r) => r.multikey, c.multikey);
  for (const [i, c] of v.keyHash.entries()) await check(`keyHash[${i}]`, "key-hash", { multikey: c.multikey }, (r) => r.output, c.output);
  for (const [i, c] of v.scid.entries()) await check(`scid[${i}]`, "scid", { entry: c.entry }, (r) => r.scid, c.scid);
  for (const [i, c] of v.entryHash.entries()) {
    await check(`entryHash[${i}]`, "entry-hash", { entry: c.entry, previousVersionId: c.previousVersionId }, (r) => r.hash, c.hash);
  }
  for (const [i, c] of v.sign.entries()) {
    const input = { document: c.document, seed: c.seed, ...(c.created ? { created: c.created } : {}) };
    await check(`sign[${i}]`, "sign", input, (r) => r.proof, c.proof);
    await check(`verify[${i}]`, "verify", { document: c.document, proof: c.proof }, (r) => r.valid, true);
    await check(`verify-tampered[${i}]`, "verify", { document: { ...c.document, extra: 1 }, proof: c.proof }, (r) => r.valid, false);
  }
}

/** Compares a resolve result to a vector's `expect`; returns a problem description or null. */
function compareResolution(expect: Json, got: Json): string | null {
  const problems: string[] = [];
  if (got?.valid !== expect.valid) problems.push(`valid: expected ${expect.valid}, got ${got?.valid}`);
  const err = got?.error ?? null;
  if (expect.error) {
    const codes = expect.error.oneOf ?? [expect.error.code];
    if (!err || !codes.includes(err.code)) problems.push(`error.code: expected ${codes.join("|")}, got ${err?.code ?? "none"}`);
    if ("version" in expect.error && err && err.version !== expect.error.version) {
      problems.push(`error.version: expected ${expect.error.version}, got ${err.version}`);
    }
  } else if (err) {
    problems.push(`unexpected error ${err.code}: ${err.message}`);
  }
  if (expect.valid && got?.valid) {
    if (!same(expect.state, got.state)) problems.push(`state: expected ${show(expect.state)}, got ${show(got.state)}`);
    if ((got.firstInvalidVersion ?? null) !== (expect.firstInvalidVersion ?? null)) {
      problems.push(`firstInvalidVersion: expected ${expect.firstInvalidVersion}, got ${got.firstInvalidVersion}`);
    }
    const warnings = (got.metadata?.warnings ?? []).map((w: Json) => w.code).sort();
    if (!same(warnings, expect.warnings ?? [])) problems.push(`warnings: expected ${show(expect.warnings)}, got ${show(warnings)}`);
    for (const [k, v] of Object.entries(expect.metadata ?? {})) {
      if (!same(v, got.metadata?.[k])) problems.push(`metadata.${k}: expected ${show(v)}, got ${show(got.metadata?.[k])}`);
    }
  }
  return problems.length ? problems.join("\n     ") : null;
}

async function resolution(d: Driver, groupFilter: string[]) {
  const dir = join(VECTORS, "resolution");
  for (const file of readdirSync(dir).sort()) {
    const group = file.replace(/\.json$/, "");
    if (groupFilter.length && !groupFilter.includes(group)) continue;
    const { cases } = JSON.parse(readFileSync(join(dir, file), "utf8"));
    for (const c of cases) {
      const res = await d.call("resolve", c.input);
      const test = `${group}/${c.name}`;
      if (!res.ok) record(d.impl.name, "resolution", test, `driver error: ${res.error}`);
      else record(d.impl.name, "resolution", test, compareResolution(c.expect, res.result));
    }
  }
}

interface Generated {
  producer: string;
  scenario: Json;
  log: string;
  witnessFile: Json[] | undefined;
}

async function generation(d: Driver): Promise<Generated[]> {
  const { scenarios } = JSON.parse(readFileSync(join(VECTORS, "generation.json"), "utf8"));
  const out: Generated[] = [];
  for (const sc of scenarios) {
    let log = "";
    let scid = "";
    const versionIds: string[] = [];
    let broken = false;
    for (const [i, step] of sc.steps.entries()) {
      const test = `${sc.name}/step${i + 1}-${step.op}`;
      const input =
        step.op === "create" ? step.input : { ...JSON.parse(JSON.stringify(step.input).replaceAll("{SCID}", scid)), log };
      const res = await d.call(step.op, input);
      if (!res.ok) {
        record(d.impl.name, "generation", test, `driver error: ${res.error}`);
        broken = true;
        break;
      }
      log = res.result.log;
      if (step.op === "create") scid = res.result.scid;
      versionIds.push(res.result.versionId);
      const line = JSON.parse(log.trimEnd().split("\n").at(-1)!);
      const problems: string[] = [];
      if (res.result.versionId !== step.expect.versionId) problems.push(`versionId: expected ${step.expect.versionId}, got ${res.result.versionId}`);
      if (step.expect.scid && res.result.scid !== step.expect.scid) problems.push(`scid: expected ${step.expect.scid}, got ${res.result.scid}`);
      if (!same(line, step.expect.line)) problems.push(`line: expected ${show(step.expect.line)}\n     got ${show(line)}`);
      if (log.split("\n").filter(Boolean).length !== i + 1) problems.push(`log has wrong number of lines`);
      record(d.impl.name, "generation", test, problems.length ? problems.join("\n     ") : null);
    }
    if (broken) continue;
    let witnessFile: Json[] | undefined;
    if (sc.witness) {
      witnessFile = [];
      for (const w of sc.witness) {
        const versionId = versionIds[w.step - 1];
        const proofs = [];
        for (const seed of w.seeds) {
          const res = await d.call("witness", { versionId, seed });
          if (res.ok) proofs.push(res.result.proof);
        }
        witnessFile.push({ versionId, proof: proofs });
      }
      record(d.impl.name, "generation", `${sc.name}/witness-file`,
        same(witnessFile, sc.witnessFile) ? null : `expected ${show(sc.witnessFile)}\n     got ${show(witnessFile)}`);
    }
    out.push({ producer: d.impl.name, scenario: sc, log, witnessFile });
  }
  return out;
}

async function cross(d: Driver, generated: Generated[]) {
  for (const g of generated) {
    const res = await d.call("resolve", { log: g.log, witness: g.witnessFile, now: g.scenario.resolve.now });
    const test = g.scenario.name;
    if (!res.ok) {
      record(d.impl.name, "cross", test, `driver error: ${res.error}`, g.producer);
      continue;
    }
    const r = res.result;
    const problem =
      !r.valid || r.error ? `did not verify: ${show(r.error)}`
      : !same(r.state, g.scenario.resolve.state) ? `state differs: ${show(r.state)}`
      : r.metadata.versionId !== g.scenario.resolve.versionId ? `versionId ${r.metadata.versionId}`
      : null;
    record(d.impl.name, "cross", test, problem, g.producer);
  }
}

/**
 * Checks did:webvh logs made by the independent didwebvh-ts implementation
 * (vectors/external). did:webvh's parameters differ from VH-Log's, so the logs
 * aren't resolved as VH-Logs; instead every shared cryptographic step is checked.
 */
async function external(d: Driver) {
  const root = join(VECTORS, "external");
  for (const source of readdirSync(root).sort()) {
    const { scenarios } = JSON.parse(readFileSync(join(root, source, "manifest.json"), "utf8"));
    for (const sc of scenarios) {
      const entries = readFileSync(join(root, source, `${sc.name}.jsonl`), "utf8").trim().split("\n").map((l) => JSON.parse(l));
      const scid = entries[0].parameters.scid;
      const check = async (test: string, op: string, input: Json, ok: (r: Json) => boolean, describe: (r: Json) => string) => {
        const res = await d.call(op, input);
        const name = `${source}/${sc.name} ${test}`;
        if (!res.ok) record(d.impl.name, "external", name, `driver error: ${res.error}`);
        else record(d.impl.name, "external", name, ok(res.result) ? null : describe(res.result));
      };
      for (const [i, entry] of entries.entries()) {
        const { proof, ...doc } = entry;
        const n = i + 1;
        if (i === 0) {
          const preliminary = JSON.parse(JSON.stringify({ ...doc, versionId: "{SCID}" }).replaceAll(scid, "{SCID}"));
          await check("#1 scid", "scid", { entry: preliminary }, (r) => r.scid === scid, (r) => `got ${r.scid}, log says ${scid}`);
        }
        const hash = entry.versionId.split("-")[1];
        const previous = i === 0 ? scid : entries[i - 1].versionId;
        await check(`#${n} entry hash`, "entry-hash", { entry: doc, previousVersionId: previous }, (r) => r.hash === hash,
          (r) => `got ${r.hash}, log says ${hash}`);
        for (const [j, p] of proof.entries()) {
          await check(`#${n} proof ${j + 1}`, "verify", { document: doc, proof: p }, (r) => r.valid === true, () => "proof did not verify");
          await check(`#${n} proof ${j + 1} rejects tampering`, "verify", { document: { ...doc, versionTime: "1999-01-01T00:00:00Z" }, proof: p },
            (r) => r.valid === false, () => "proof verified over tampered content");
        }
        const committed: string[] = i > 0 ? entries[i - 1].parameters.nextKeyHashes ?? [] : [];
        if (committed.length) {
          for (const k of entry.parameters.updateKeys) {
            await check(`#${n} pre-rotation key hash`, "key-hash", { multikey: k }, (r) => committed.includes(r.output),
              (r) => `${r.output} not in previous nextKeyHashes`);
          }
        }
      }
      if (sc.witness) {
        const file = JSON.parse(readFileSync(join(root, source, `${sc.name}.witness.json`), "utf8"));
        for (const record of file) {
          for (const [j, p] of record.proof.entries()) {
            await check(`witness proof ${record.versionId.split("-")[0]}.${j + 1}`, "verify", { document: { versionId: record.versionId }, proof: p },
              (r) => r.valid === true, () => "witness proof did not verify over {versionId}");
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------- main

const { values } = parseArgs({
  options: {
    impl: { type: "string", multiple: true, default: [] },
    suite: { type: "string", multiple: true, default: [] },
    group: { type: "string", multiple: true, default: [] },
    verbose: { type: "boolean", default: false },
    list: { type: "boolean", default: false },
    markdown: { type: "string" },
    "update-readme": { type: "boolean", default: false },
  },
});
const registry: ImplConfig[] = JSON.parse(readFileSync(join(ROOT, "implementations.json"), "utf8")).implementations;
const selected = registry.filter((i) => values.impl!.length === 0 || values.impl!.includes(i.name));
const ALL_SUITES = ["primitives", "resolution", "generation", "cross", "external"];
const suites = values.suite!.length ? values.suite! : ALL_SUITES;
const impls = selected.filter((i) => {
  const error = build(i);
  if (error) record(i.name, "build", "build", error);
  return !error;
});
const drivers = impls.map((i) => new Driver(i));

await Promise.all(
  drivers.map(async (d) => {
    if (suites.includes("primitives")) await primitives(d);
    if (suites.includes("resolution")) await resolution(d, values.group!);
    if (suites.includes("external")) await external(d);
  }),
);
if (suites.includes("generation") || suites.includes("cross")) {
  const generated = (await Promise.all(drivers.map((d) => generation(d)))).flat();
  if (suites.includes("cross")) await Promise.all(drivers.map((d) => cross(d, generated)));
}
for (const d of drivers) d.close();

// ---------------------------------------------------------------- report

const SUITE_TITLES: Record<string, string> = {
  primitives: "Primitives",
  resolution: "Resolution",
  generation: "Generation",
  cross: "Cross",
  external: "didwebvh-ts",
};
const failures = results.filter((r) => r.problem !== null);
const tally = (rs: Result[]) => ({ pass: rs.filter((r) => r.problem === null).length, total: rs.length });
const cell = (rs: Result[], plain: boolean) => {
  const { pass, total } = tally(rs);
  if (total === 0) return "–";
  return pass === total ? `${plain ? "✓" : "✅"} ${total}` : `${plain ? "✗" : "❌"} ${pass}/${total}`;
};
const of = (impl: string, suite: string) => results.filter((r) => r.impl === impl && r.suite === suite);
const buildFailed = (impl: string) => results.some((r) => r.impl === impl && r.suite === "build");

// Every test. Conformance runs are grouped per implementation (collapsible in
// GitHub Actions); interoperability runs are printed ungrouped, one line per
// producer → resolver pair, so they are visible without expanding anything.
const ci = Boolean(process.env.GITHUB_ACTIONS);
if (values.list) {
  console.log("\n━━ Conformance: each implementation against the shared vectors");
  for (const impl of selected) {
    for (const suite of ["build", ...suites.filter((x) => x !== "cross")]) {
      const rs = of(impl.name, suite);
      if (!rs.length) continue;
      const title = `${impl.name} › ${suite} (${cell(rs, true)})`;
      console.log(ci ? `::group::${title}` : `\n── ${title}`);
      for (const r of rs) {
        console.log(`  ${r.problem === null ? "✓" : "✗"} ${r.test}`);
        if (r.problem !== null) console.log(`      ${r.problem.replaceAll("\n", "\n      ")}`);
      }
      if (ci) console.log("::endgroup::");
    }
  }
  if (suites.includes("cross")) {
    console.log("\n━━ Interoperability: logs (and witness files) generated by one implementation, resolved by another");
    const names = selected.map((i) => i.name);
    const width = Math.max(...names.map((n) => n.length));
    for (const producer of names) {
      for (const resolver of names) {
        if (producer === resolver) continue;
        const rs = results.filter((r) => r.suite === "cross" && r.producer === producer && r.impl === resolver);
        if (!rs.length) continue;
        const marks = rs.map((r) => `${r.problem === null ? "✓" : "✗"} ${r.test}`).join("  ");
        console.log(`  ${producer.padEnd(width)} → ${resolver.padEnd(width)}  ${marks}`);
        for (const r of rs.filter((x) => x.problem !== null)) console.log(`      ${r.test}: ${r.problem}`);
      }
    }
  }
}

const pad = (s: string, n: number) => s.padEnd(n);
console.log("\n" + pad("implementation", 16) + suites.map((s) => pad(s, 14)).join(""));
for (const impl of selected) {
  const cells = suites.map((s) => pad(buildFailed(impl.name) ? "build failed" : cell(of(impl.name, s), true), 14));
  console.log(pad(impl.name, 16) + cells.join(""));
}

function markdown(): string {
  const names = selected.map((i) => i.name);
  const lines = [
    `| Implementation | ${suites.map((s) => SUITE_TITLES[s] ?? s).join(" | ")} |`,
    `| --- | ${suites.map(() => "---").join(" | ")} |`,
    ...names.map((n) => `| ${n} | ${suites.map((s) => (buildFailed(n) ? "build failed" : cell(of(n, s), false))).join(" | ")} |`),
  ];
  if (suites.includes("cross")) {
    lines.push(
      "",
      "Cross-resolution: each row's implementation resolving logs and witness files generated by each column's implementation.",
      "",
      `| resolver ↓ / producer → | ${names.join(" | ")} |`,
      `| --- | ${names.map(() => "---").join(" | ")} |`,
      ...names.map(
        (r) => `| ${r} | ${names.map((p) => cell(results.filter((x) => x.suite === "cross" && x.impl === r && x.producer === p), false)).join(" | ")} |`,
      ),
    );
  }
  return lines.join("\n");
}

const summary = [
  `### VH-Log interop matrix`,
  "",
  markdown(),
  "",
  failures.length ? `**${failures.length} failure(s)**` : `**All ${results.length} checks passed.**`,
  ...failures.slice(0, 50).map((f) => `- \`${f.impl}\` ${f.suite} › ${f.test}: ${f.problem!.split("\n")[0]}`),
].join("\n");
if (values.markdown) writeFileSync(values.markdown, summary + "\n", { flag: "a" });

if (values["update-readme"]) {
  if (failures.length) {
    console.error("\nnot updating README.md: there are failures");
  } else if (values.impl!.length || values.suite!.length || values.group!.length) {
    console.error("\nnot updating README.md: run without --impl/--suite/--group");
  } else {
    const readme = join(ROOT, "README.md");
    const text = readFileSync(readme, "utf8");
    const start = "<!-- interop-matrix:start -->";
    const end = "<!-- interop-matrix:end -->";
    if (!text.includes(start) || !text.includes(end)) throw new Error("README.md has no interop-matrix markers");
    const block = `${start}\n<!-- Generated by \`node harness/run.ts --update-readme\`; CI fails if this is out of date. -->\n\n${markdown()}\n\n${end}`;
    writeFileSync(readme, text.slice(0, text.indexOf(start)) + block + text.slice(text.indexOf(end) + end.length));
    console.log("\nupdated README.md");
  }
}

if (failures.length) {
  console.log(`\n${failures.length} failure(s):`);
  const shown = values.verbose ? failures : failures.slice(0, 40);
  for (const f of shown) console.log(`\n  [${f.impl}] ${f.suite} › ${f.test}\n     ${f.problem}`);
  if (shown.length < failures.length) console.log(`\n  … ${failures.length - shown.length} more (use --verbose)`);
  process.exitCode = 1;
} else {
  console.log(`\nall ${results.length} checks passed`);
}
