// Runs the independent @interop/did-method-webvh did:vh resolver over this
// repository's did:vh resolution vectors and lists where it disagrees. It is a
// report, not a test: some differences are choices our profile makes and the
// spec leaves open, and some are because its resolver retrieves srcLog and
// srcWitness where ours are offline (run with network "none" here).
//
//   node tools/external/interop-did-method-webvh-check.mjs /tmp/interop vectors/didvh
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
const [pkgDir, vecDir] = process.argv.slice(2);
const vh = await import(join(pkgDir, "node_modules/@interop/did-method-webvh/dist/vh.js"));
const canon = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.entries(x).sort()) : x));
let agree = 0, total = 0; const diffs = [];
for (const f of readdirSync(join(vecDir, "resolution")).sort()) {
  for (const c of JSON.parse(readFileSync(join(vecDir, "resolution", f), "utf8")).cases) {
    total++;
    const o = { ...c.input.options, local: !c.input.remote, network: "none" };
    if (typeof o.versionTime === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(Z|\+00:00)$/.test(o.versionTime)) o.versionTime = new Date(o.versionTime);
    let r;
    try { r = await vh.resolveDID(c.input.did, o); } catch (e) { r = { thrown: String(e).slice(0, 160) }; }
    const meta = r?.didResolutionMetadata ?? {};
    const want = c.expect.error ?? "ok", got = r.thrown ? "THROW" : meta.error ?? "ok";
    let why = null;
    if (want !== got) why = `error: want ${want}, got ${got} (${String(meta.problemDetails?.detail ?? meta.message ?? r.thrown ?? "").slice(0, 140)})`;
    else if (want === "ok") {
      if (canon(c.expect.didDocument) !== canon(r.didDocument ?? null)) why = "didDocument differs";
      else for (const k of ["versionId", "deactivated", "ttl", "watchers", "created", "updated"]) if (canon(c.expect.didDocumentMetadata?.[k]) !== canon(r.didDocumentMetadata?.[k])) { why = `metadata.${k}: want ${canon(c.expect.didDocumentMetadata?.[k])}, got ${canon(r.didDocumentMetadata?.[k])}`; break; }
    }
    if (why) diffs.push(`${f.replace(".json", "")}/${c.name}: ${why}`); else agree++;
  }
}
console.log(`agree ${agree}/${total}`); for (const d of diffs) console.log("  " + d);
