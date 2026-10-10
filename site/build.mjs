// Builds site/index.html from the repository itself: the code in the score is
// read from the implementations by line range, and the interop numbers are
// parsed from the README's generated matrix. Run: node site/build.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SITE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(SITE, "..");
const IMPL = path.join(ROOT, "implementations");
const REPO = "https://github.com/brianorwhatever/vh";
const REF = process.env.GITHUB_SHA || "main";

const LANGS = [
  { id: "typescript", name: "TypeScript", short: "TS" },
  { id: "rust", name: "Rust", short: "Rust" },
  { id: "python", name: "Python", short: "Py" },
  { id: "elixir", name: "Elixir", short: "Ex" },
  { id: "go", name: "Go", short: "Go" },
  { id: "swift", name: "Swift", short: "Swift" },
  { id: "kotlin", name: "Kotlin", short: "Kt" },
  { id: "zig", name: "Zig", short: "Zig" },
  { id: "common-lisp", name: "Common Lisp", short: "CL" },
  { id: "forth", name: "Forth", short: "Forth" },
];
const WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve"];
const N = WORDS[LANGS.length] || String(LANGS.length);
const Ncap = N[0].toUpperCase() + N.slice(1);
const ORDINALS = ["first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth", "tenth", "eleventh", "twelfth", "thirteenth"];
const NEXT = ORDINALS[LANGS.length] || "new";
const NAMES = LANGS.slice(0, -1).map((l) => l.name).join(", ") + " and " + LANGS.at(-1).name;

// Each movement: the beats, then per language the line ranges and the marks.
// A mark is [beat, exact text]; the build fails if the text is not found, so
// a refactor that moves the code shows up here rather than on the page.
const MOVEMENTS = [
  {
    id: "signing",
    title: "The signing input",
    lede: "Every eddsa-jcs-2022 proof signs SHA-256(JCS(proof config)) followed by SHA-256(JCS(document)). Sixty-four bytes, built the same way in every language.",
    beats: ["Hash the proof configuration", "Hash the document", "Join the two digests"],
    parts: {
      typescript: { ranges: [["typescript/src/proof.ts", 33, 35]], marks: [[1, "sha256(canonicalize(proofConfig))"], [2, "sha256(canonicalize(document))"], [3, "Uint8Array.from(["]] },
      rust: { ranges: [["rust/src/proof.rs", 120, 124]], marks: [[1, "sha256(canonicalize(&Value::Object(config.clone())).as_bytes())"], [2, "sha256(canonicalize(document).as_bytes())"], [3, "input.extend_from_slice"]] },
      python: { ranges: [["python/src/vh_log/proof.py", 50, 51]], marks: [[1, "sha256(canonicalize(proof_config))"], [2, "sha256(canonicalize(document))"], [3, " + "]] },
      elixir: { ranges: [["elixir/lib/vh_log/proof.ex", 109, 111]], marks: [[1, "Hash.sha256(JCS.canonicalize(config))"], [2, "Hash.sha256(JCS.canonicalize(document))"], [3, "<>"]] },
      go: { ranges: [["go/proof.go", 40, 53]], marks: [[1, "Canonicalize(config)"], [1, "sha256.Sum256(toUTF8(c))"], [2, "Canonicalize(document)"], [2, "sha256.Sum256(toUTF8(d))"], [3, "append(hc[:], hd[:]...)"]] },
      swift: { ranges: [["swift/Sources/VHLog/Proof.swift", 30, 33]], marks: [[1, "Multihash.sha256(try JCS.canonicalBytes(.object(config)))"], [2, "Multihash.sha256(try JCS.canonicalBytes(document))"], [3, " + "]] },
      kotlin: { ranges: [["kotlin/src/main/kotlin/org/vhlog/Proof.kt", 33, 34]], marks: [[1, "Hashes.sha256(Jcs.canonicalize(proofConfig))"], [2, "Hashes.sha256(Jcs.canonicalize(document))"], [3, " + "]] },
      zig: { ranges: [["zig/src/proof.zig", 29, 38]], marks: [[1, "json.canonicalize(allocator, config)"], [1, "Sha256.hash(c, out[0..32], .{})"], [2, "json.canonicalize(allocator, document)"], [2, "Sha256.hash(d, out[32..64], .{})"], [3, "var out: [64]u8 = undefined"]] },
      "common-lisp": { ranges: [["common-lisp/src/proof.lisp", 44, 47]], marks: [[1, "(sha256 (utf8 (canonicalize proof-config)))"], [2, "(sha256 (utf8 (canonicalize document)))"], [3, "concat-octets"]] },
      forth: {"ranges": [["forth/crypto.fs", 53, 55]], "marks": [[1, "config jcs j-sha"], [2, "document without-proof jcs j-sha"], [3, "j-cat"]]},
    },
  },
  {
    id: "entry-hash",
    title: "The entry hash",
    lede: "Each versionId carries a hash of its entry, taken with the proof removed and the previous versionId in its place. That is what chains the log.",
    beats: ["Drop the proof", "Put the previous versionId in", "Canonicalise with JCS", "Hash to a base58btc multihash"],
    parts: {
      typescript: { ranges: [["typescript/src/log.ts", 28, 31]], marks: [[1, "withoutProof(entry)"], [2, "versionId: previousVersionId"], [3, "canonicalize("], [4, "hashB58("]] },
      rust: { ranges: [["rust/src/log.rs", 28, 36]], marks: [[1, "without_proof(entry)"], [2, "document.insert("], [2, "\"versionId\".into(),"], [2, "Value::String(previous_version_id.into()),"], [3, "canonicalize("], [4, "hash_b58("]] },
      python: { ranges: [["python/src/vh_log/log.py", 55, 57]], marks: [[1, "_without_proof(entry)"], [2, "\"versionId\": previous_version_id"], [3, "canonicalize("], [4, "hash_b58("]] },
      elixir: { ranges: [["elixir/lib/vh_log/log.ex", 32, 43]], marks: [[1, "Map.delete(\"proof\")"], [2, "Map.put(\"versionId\", previous_version_id)"], [3, "JCS.canonicalize()"], [4, "Hash.b58()"]] },
      go: { ranges: [["go/log.go", 35, 45]], marks: [[1, "entry.without(\"proof\")"], [2, "doc.Set(\"versionId\", previousVersionID)"], [3, "Canonicalize(doc)"], [4, "HashString(c)"]] },
      swift: { ranges: [["swift/Sources/VHLog/Log.swift", 38, 42]], marks: [[1, "entry.removing(\"proof\")"], [2, ".setting(\"versionId\", .string(previousVersionId))"], [3, "JCS.canonicalBytes("], [4, "Multihash.hashB58("]] },
      kotlin: { ranges: [["kotlin/src/main/kotlin/org/vhlog/Log.kt", 33, 36]], marks: [[1, "entry.without(\"proof\")"], [2, ".with(\"versionId\", JsonString(previousVersionId))"], [3, "Jcs.canonicalize("], [4, "Hashes.hashB58("]] },
      zig: { ranges: [["zig/src/log.zig", 17, 21], ["zig/src/log.zig", 29, 36]], marks: [[1, "json.without(a, entry, \"proof\")"], [2, "json.with("], [2, "\"versionId\", .{ .string = previous_version_id }"], [3, "json.canonicalize(allocator, v)"], [4, "codec.hashString(allocator, c)"]] },
      "common-lisp": { ranges: [["common-lisp/src/log.lisp", 33, 36]], marks: [[1, "(jwithout entry \"proof\")"], [2, "\"versionId\" previous-version-id"], [2, "(jwith "], [3, "(canonicalize "], [4, "hash-string"]] },
      forth: {"ranges": [["forth/crypto.fs", 75, 76]], "marks": [[1, "entry without-proof"], [2, "previous pre s\" versionId\" put"], [3, "jcs"], [4, "multihash"]]},
    },
  },
  {
    id: "scid",
    title: "Verifying the SCID",
    lede: "The identifier is a hash of the first entry as it was before the identifier existed. To check it, a resolver puts the {SCID} placeholder back, as text, and hashes again.",
    beats: ["Check it is a SHA-256 multihash", "Drop the proof, versionId back to {SCID}", "Replace the SCID with {SCID} in the text", "Hash again and compare"],
    parts: {
      typescript: { ranges: [["typescript/src/verify.ts", 208, 215]], marks: [[1, "checkSha256Multihash(scid)"], [2, "{ proof: _, ...rest } = entry"], [2, "versionId: SCID_PLACEHOLDER"], [3, ".replaceAll(scid, SCID_PLACEHOLDER)"], [4, "computeScid(JSON.parse(text)) !== scid"]] },
      rust: { ranges: [["rust/src/verify.rs", 470, 504]], marks: [[1, "check_sha256_multihash(scid)"], [2, "rest.remove(\"proof\");"], [2, "rest.insert(\"versionId\".into(), Value::String(SCID_PLACEHOLDER.into()));"], [3, ".replace(scid, SCID_PLACEHOLDER)"], [4, "compute_scid(&preliminary) != scid"]] },
      python: { ranges: [["python/src/vh_log/verify.py", 355, 364]], marks: [[1, "check_sha256_multihash(scid)"], [2, "k != \"proof\""], [2, "\"versionId\": SCID_PLACEHOLDER"], [3, ".replace(scid, SCID_PLACEHOLDER)"], [4, "compute_scid(parse_json(text)) != scid"]] },
      elixir: { ranges: [["elixir/lib/vh_log/verifier.ex", 258, 283]], marks: [[1, "Hash.check_sha256(scid)"], [2, "Map.delete(\"proof\")"], [2, "Map.put(\"versionId\", placeholder)"], [3, "Log.replace_text(scid, placeholder)"], [4, "Log.scid(preliminary) == scid"]] },
      go: { ranges: [["go/verify.go", 421, 438]], marks: [[1, "CheckSHA256Multihash(scid)"], [2, "entry.without(\"proof\")"], [2, "preliminary.Set(\"versionId\", SCIDPlaceholder)"], [3, "strings.ReplaceAll(Stringify(preliminary), scid, SCIDPlaceholder)"], [4, "ComputeSCID(parsed.(*Object))"], [4, "computed != scid"]] },
      swift: { ranges: [["swift/Sources/VHLog/Verify.swift", 276, 285]], marks: [[1, "Multihash.check(scid)"], [2, "entry.removing(\"proof\").setting(\"versionId\", .string(scidPlaceholder))"], [3, "replacingText(in: preliminary, scid, with: scidPlaceholder)"], [4, "computeScid(restored)"], [4, "bytesEqual(computed, scid)"]] },
      kotlin: { ranges: [["kotlin/src/main/kotlin/org/vhlog/Verify.kt", 219, 234]], marks: [[1, "Hashes.checkSha256Multihash(scid)"], [2, "entry.without(\"proof\").with(\"versionId\", JsonString(LogController.SCID_PLACEHOLDER))"], [3, "LogController.replaceInText("], [4, "LogController.computeScid(preliminary) != scid"]] },
      zig: { ranges: [["zig/src/resolve.zig", 253, 265], ["zig/src/log.zig", 44, 55]], marks: [[1, "codec.classifyMultihash(a, params.scid)"], [4, "!std.mem.eql(u8, recomputed, params.scid)"], [2, "json.without(a, entry, \"proof\")"], [2, "\"versionId\", .{ .string = scid_placeholder }"], [3, "replaceAll(a, text, the_scid, scid_placeholder)"], [4, "hashValue(allocator, reparsed.value)"]] },
      "common-lisp": { ranges: [["common-lisp/src/resolve.lisp", 224, 231]], marks: [[1, "(decode-multihash scid) :sha-256"], [2, "(jwith (jwithout json \"proof\") \"versionId\" +scid-placeholder+)"], [3, "(replace-all (to-json preliminary) scid +scid-placeholder+)"], [4, "(string= scid (compute-scid restored))"]] },
      forth: {"ranges": [["forth/validation.fs", 83, 87]], "marks": [[1, "id hash?"], [2, "entry without-proof"], [2, "placeholder pre s\" versionId\" put"], [3, "pre j-dump id placeholder j-replace"], [4, "json-parse scid id j-equal"]]},
    },
  },
  {
    id: "pre-rotation",
    title: "Pre-rotation",
    lede: "A log can commit to the hashes of its next keys. While it does, every new update key must hash to one of those commitments, or the entry is rejected.",
    beats: ["Is pre-rotation active?", "Both key lists must be explicit", "Hash each new update key", "Each hash must have been committed"],
    parts: {
      typescript: { ranges: [["typescript/src/verify.ts", 157, 164]], marks: [[1, "previous && previous.nextKeyHashes.length > 0"], [2, "!(\"updateKeys\" in raw)"], [2, "!(\"nextKeyHashes\" in raw)"], [3, "keyHash(key)"], [4, "previous.nextKeyHashes.includes("]] },
      rust: { ranges: [["rust/src/verify.rs", 334, 352]], marks: [[1, "previous.filter(|p| !p.next_key_hashes.is_empty())"], [2, "let Some(keys) = &update_keys else"], [2, "next_key_hashes.is_none()"], [3, "key_hash(k)"], [4, "!prev.next_key_hashes.contains("]] },
      python: { ranges: [["python/src/vh_log/verify.py", 282, 293]], marks: [[1, "previous is not None and previous.next_key_hashes"], [2, "\"updateKeys\" not in raw"], [2, "\"nextKeyHashes\" not in raw"], [3, "key_hash(key)"], [4, "not in previous.next_key_hashes"]] },
      elixir: { ranges: [["elixir/lib/vh_log/parameters.ex", 210, 232]], marks: [[1, "%__MODULE__{next_key_hashes: []}"], [2, "not Map.has_key?(raw, \"updateKeys\")"], [2, "not Map.has_key?(raw, \"nextKeyHashes\")"], [3, "Hash.key_hash(&1)"], [4, "not in committed"]] },
      go: { ranges: [["go/verify.go", 316, 328]], marks: [[1, "previous != nil && len(previous.NextKeyHashes) > 0"], [2, "updateKeys == nil"], [2, "nextKeyHashes == nil"], [3, "KeyHash(k)"], [4, "slices.Contains(previous.NextKeyHashes, "]] },
      swift: { ranges: [["swift/Sources/VHLog/Verify.swift", 214, 221]], marks: [[1, "let previous, !previous.nextKeyHashes.isEmpty"], [2, "guard let keys = updateKeys else"], [2, "guard nextKeyHashes != nil else"], [3, "Multihash.keyHash(key)"], [4, "containsExactly(previous.nextKeyHashes, "]] },
      kotlin: { ranges: [["kotlin/src/main/kotlin/org/vhlog/Verify.kt", 161, 168]], marks: [[1, "previous != null && previous.nextKeyHashes.isNotEmpty()"], [2, "updateKeys == null"], [2, "nextKeyHashes == null"], [3, "Hashes.keyHash(key)"], [4, "!in previous.nextKeyHashes"]] },
      zig: { ranges: [["zig/src/resolve.zig", 355, 367]], marks: [[1, "pp.next_key_hashes.len > 0"], [2, "update_keys == null"], [2, "next_key_hashes == null"], [3, "codec.hashString(a, key)"], [4, "std.mem.eql(u8, c, h)"]] },
      "common-lisp": { ranges: [["common-lisp/src/resolve.lisp", 155, 162]], marks: [[1, "(and prior (plusp (length (params-next-key-hashes prior))))"], [2, "(jhas raw \"updateKeys\")"], [2, "(jhas raw \"nextKeyHashes\")"], [3, "(key-hash key)"], [4, "unless (find"], [4, "(params-next-key-hashes prior) :test #'string=)"]] },
      forth: {"ranges": [["forth/validation.fs", 53, 59]], "marks": [[1, "first 0= old s\" nextKeyHashes\" j-get j-size 0> and"], [2, "p s\" updateKeys\" j-has p s\" nextKeyHashes\" j-has and"], [3, "keys i j-at multihash"], [4, "contains?"]]},
    },
  },
];

// The parts: why each implementation exists (from the README) and where its library code lives.
const PARTS = {
  typescript: { note: "The reference. It generates the shared vectors. No runtime dependencies.", src: ["src"], skip: [/driver\.ts$/] },
  rust: { note: "A library crate with a small driver binary.", src: ["src"], skip: [/\/bin\//] },
  python: { note: "Python 3.12, packaged with uv.", src: ["src/vh_log"], skip: [/driver\.py$/] },
  elixir: { note: "Resolution is a pure fold over immutable entries. Ed25519 and SHA-256 come from OTP. Suited to witness and watcher services.", src: ["lib"], skip: [/driver\.ex$/] },
  go: { note: "Standard library only. Most identity and transparency-log infrastructure is written in Go.", src: ["."], skip: [/_test\.go$/, /\/cmd\//] },
  swift: { note: "For iOS wallets. Builds on Linux through swift-crypto.", src: ["Sources/VHLog"], skip: [] },
  kotlin: { note: "For Android, EUDI wallets and Java callers. Ed25519 comes from the JDK.", src: ["src/main"], skip: [/[Dd]river/] },
  zig: { note: "Clean-room: written only from the spec, the profile and the vectors, without reading the other implementations. Standard library only.", src: ["src"], skip: [/tests\.zig$/, /main\.zig$/] },
  "common-lisp": { note: "Clean-room too, for SBCL, from the same documents. Cryptography from Ironclad. Its notes record what the spec still leaves ambiguous.", src: ["src"], skip: [/driver\.lisp$/] },
  forth: { note: "Clean-room Gforth. Protocol logic and JCS traversal in Forth, with native JSON/Unicode support and libsodium cryptography.", src: ["."], skip: [/driver\.fs$/, /test\.fs$/] },
};
const EXT = { typescript: ".ts", rust: ".rs", python: ".py", elixir: ".ex", go: ".go", swift: ".swift", kotlin: ".kt", zig: ".zig", "common-lisp": ".lisp", forth: ".fs" };

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const read = (rel) => fs.readFileSync(path.join(IMPL, rel), "utf8").split("\n");

function extract(ranges) {
  const blocks = ranges.map(([file, from, to]) => read(file).slice(from - 1, to).map((l) => l.replace(/\t/g, "    ")));
  const lines = [];
  blocks.forEach((block, i) => {
    const indent = Math.min(...block.filter((l) => l.trim()).map((l) => l.match(/^ */)[0].length));
    if (i > 0) lines.push("⋯");
    lines.push(...block.map((l) => l.slice(indent)));
  });
  return lines.join("\n");
}

function commentMask(text, lisp = false) {
  const mask = new Uint8Array(text.length);
  let pos = 0, heredoc = false, docstring = false;
  for (const line of text.split("\n")) {
    const t = line.trim();
    const lispDoc = lisp && (docstring || t.startsWith('"'));
    const isComment = heredoc || lispDoc || (lisp ? t.startsWith(";") : /^(\/\/|#|\/\*\*|\*|@doc|"""|⋯)/.test(t)) || t === "⋯";
    if (/^@doc """$/.test(t)) heredoc = true;
    else if (heredoc && t === '"""') heredoc = false;
    if (lispDoc) docstring = !(t.endsWith('"') && (docstring || t.length > 1));
    if (isComment) mask.fill(1, pos, pos + line.length);
    pos += line.length + 1;
  }
  return mask;
}

function render(text, marks, where, lisp = false) {
  const beat = new Uint8Array(text.length);
  for (const [n, needle] of marks) {
    const at = text.indexOf(needle);
    if (at < 0) throw new Error(`${where}: mark not found: ${needle}`);
    for (let i = at; i < at + needle.length; i++) {
      if (beat[i] && beat[i] !== n) throw new Error(`${where}: marks overlap at: ${needle}`);
      beat[i] = n;
    }
  }
  const comment = commentMask(text, lisp);
  // One block per line, tagged with the beats it holds, so a narrow screen can
  // show just the signature and the line being played.
  const lines = [];
  let sigDone = false;
  // The line that heads the excerpt: its declaration, else its first line of code.
  const all = text.split("\n");
  const offsets = all.map((_, k) => all.slice(0, k).reduce((a, l) => a + l.length + 1, 0));
  const isCode = (k) => all[k].trim() && !comment[offsets[k] + all[k].search(/\S/)];
  const decl = all.findIndex((l, k) => isCode(k) && /^\s*((export|pub|public|private|static|async)\s+)*(function|fn|def|defp|func|fun)\b|^\(defun\b/.test(l.trim()));
  const sigLine = decl >= 0 ? decl : all.findIndex((l, k) => isCode(k));
  const i0 = (start) => text.slice(0, start).split("\n").length - 1;
  for (let start = 0; start <= text.length; ) {
    let end = text.indexOf("\n", start);
    if (end < 0) end = text.length;
    let html = "";
    const has = new Set();
    for (let i = start; i < end; ) {
      let j = i;
      while (j < end && beat[j] === beat[i] && comment[j] === comment[i]) j++;
      let s = esc(text.slice(i, j));
      if (beat[i]) { s = `<mark data-b="${beat[i]}">${s}</mark>`; has.add(beat[i]); }
      if (comment[i]) s = `<span class="c">${s}</span>`;
      html += s;
      i = j;
    }
    const sig = !sigDone && end > start && i0(start, end) === sigLine;
    if (sig) sigDone = true;
    lines.push(`<span class="ln"${sig ? " data-sig" : ""}${has.size ? ` data-has="${[...has].join(" ")}"` : ""}><span class="lc">${html || " "}</span></span>`);
    start = end + 1;
  }
  return lines.join("");
}

function staff(lang, part, movement) {
  const [file, from] = part.ranges[0];
  const last = part.ranges.at(-1);
  const sameFile = part.ranges.every((r) => r[0] === file);
  const to = sameFile ? last[2] : part.ranges[0][2];
  const href = `${REPO}/blob/${REF}/implementations/${file}#L${from}-L${to}`;
  const code = render(extract(part.ranges), part.marks, `${movement.id}/${lang.id}`, lang.id === "common-lisp");
  return `<div class="staff" data-lang="${lang.id}">
        <div class="part"><span class="instrument">${lang.name}</span><a class="where" href="${href}">${path.basename(file)}:${from}</a></div>
        <div class="code"><span class="cue" aria-hidden="true"></span><pre tabindex="0" aria-label="${lang.name}: ${esc(movement.title)}"><code>${code}</code></pre></div>
      </div>`;
}

const ROMAN = ["I", "II", "III", "IV", "V"];

function movementPanel(m, i) {
  return `<section class="movement" id="m-${m.id}" role="tabpanel" aria-labelledby="t-${m.id}" data-movement="${m.id}">
    <h2 class="m-title"><span class="numeral">${ROMAN[i]}</span> ${esc(m.title)}</h2>
    <p class="m-lede">${esc(m.lede)}</p>
    <ol class="beats" aria-label="Beats">
      ${m.beats.map((b, k) => `<li><button type="button" data-beat="${k + 1}"><span class="n">${k + 1}</span> ${esc(b)}</button></li>`).join("\n      ")}
    </ol>
    <div class="system">
      ${LANGS.map((l) => staff(l, m.parts[l.id], m)).join("\n      ")}
    </div>
  </section>`;
}

// --- facts parsed from the repository -------------------------------------------------

function readmeMatrix() {
  const md = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");
  const block = md.slice(md.indexOf("<!-- interop-matrix:start -->"), md.indexOf("<!-- interop-matrix:end -->"));
  const rows = block.split("\n").filter((l) => l.startsWith("| ") && !l.startsWith("| ---"));
  const suiteHeader = rows.find((r) => r.startsWith("| Implementation"));
  const suites = suiteHeader.split("|").slice(2, -1).map((s) => s.trim());
  const perImpl = {}, cross = {};
  let producers = null;
  for (const r of rows) {
    const cells = r.split("|").slice(1, -1).map((s) => s.trim());
    if (cells[0] === "Implementation") continue;
    if (cells[0].startsWith("resolver")) { producers = cells.slice(1); continue; }
    const parsed = cells.slice(1).map((c) => ({ ok: c.startsWith("✅"), n: Number(c.replace(/[^\d]/g, "")) }));
    if (producers) cross[cells[0]] = parsed; else perImpl[cells[0]] = parsed;
  }
  return { suites, perImpl, cross, producers };
}

function sourceLines(lang) {
  const p = PARTS[lang];
  let total = 0;
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (!/^(\.|node_modules|target|_build|deps|build|zig-out|bin)/.test(e.name)) walk(full); continue; }
      if (!e.name.endsWith(EXT[lang]) || p.skip.some((re) => re.test(full))) continue;
      total += fs.readFileSync(full, "utf8").split("\n").filter((l) => l.trim()).length;
    }
  };
  for (const s of p.src) walk(path.join(IMPL, lang, s));
  return total;
}

const matrix = readmeMatrix();
const perImplTotal = matrix.perImpl.typescript.reduce((a, c) => a + c.n, 0);
const allGreen = Object.values(matrix.perImpl).every((r) => r.every((c) => c.ok)) && Object.values(matrix.cross).every((r) => r.every((c) => c.ok));
if (!allGreen) console.warn("warning: the README matrix is not all green; the page says what it says");
const runTotal = Object.values(matrix.perImpl).reduce((a, r) => a + r.reduce((x, c) => x + c.n, 0), 0);
const pairings = Object.keys(matrix.cross).length * matrix.producers.length;
const logsPerPairing = matrix.cross.typescript[0].n;
const spec = JSON.parse(fs.readFileSync(path.join(ROOT, "spec.lock.json"), "utf8"));
// The driver operations, read from the protocol document so the list can't drift.
const protocol = fs.readFileSync(path.join(ROOT, "docs/interop-protocol.md"), "utf8");
const OPS = [...new Set([...protocol.matchAll(/^\| `([a-z-]+)` \|/gm), ...protocol.matchAll(/"op": "([a-z-]+)"/g)].map((m) => m[1]))];
const specNotes = (fs.readFileSync(path.join(ROOT, "docs/spec-notes.md"), "utf8").match(/^\d+\. \*\*/gm) || []).length;
const fmt = (n) => n.toLocaleString("en-US");
const short = Object.fromEntries(LANGS.map((l) => [l.id, l.short]));
for (const name of matrix.producers) if (!short[name]) console.warn(`warning: ${name} is in the README matrix but not in LANGS; add its part to site/build.mjs`);
const SUITE_TEXT = {
  Primitives: "byte-exact encodings, hashes and signatures",
  Resolution: "the verdict on every vector log, valid and invalid",
  Generation: "entries that must match the reference exactly",
  Cross: `logs and witness files from all ${N} producers`,
  "didwebvh-ts": "logs from the independent did:webvh implementation",
};

const okPairings = Object.values(matrix.cross).flat().filter((c) => c.ok && c.n === logsPerPairing).length;
const crossTable = `<figure class="cross-fig">
      <p class="claim"><span class="num">${okPairings}</span> of <span class="num">${pairings}</span> pairings resolve every file.</p>
      <table class="cross">
        <caption>Resolver down, producer across. Each cell is the number of generated logs and witness files that resolved, out of ${logsPerPairing}. The diagonal, in italics, is each one resolving its own. The TypeScript row and column, ruled, are the reference.</caption>
        <thead><tr><td></td>${matrix.producers.map((p) => `<th scope="col"><span>${short[p] || p}</span></th>`).join("")}</tr></thead>
        <tbody>
          ${Object.entries(matrix.cross).map(([r, cells]) => `<tr><th scope="row">${short[r] || r}</th>${cells.map((c, k) => `<td class="${c.ok ? "ok" : "bad"}${matrix.producers[k] === r ? " self" : ""}${r === "typescript" || matrix.producers[k] === "typescript" ? " ref" : ""}" title="${matrix.producers[k]} → ${r}">${c.n}</td>`).join("")}</tr>`).join("\n          ")}
        </tbody>
      </table>
      </figure>`;

const suites = matrix.suites.map((s, k) => `<div><dt>${fmt(matrix.perImpl.typescript[k].n)}</dt><dd><b>${esc(s)}</b> ${esc(SUITE_TEXT[s] || "")}</dd></div>`).join("\n          ");

const partsList = LANGS.map((l) => `<li>
          <span class="instrument">${l.name}</span>
          <p>${esc(PARTS[l.id].note)}</p>
          <a class="lines" href="${REPO}/tree/${REF}/implementations/${l.id}"><span class="num">${fmt(sourceLines(l.id))}</span> lines</a>
        </li>`).join("\n        ");

const tabs = MOVEMENTS.map((m, i) => `<button type="button" role="tab" id="t-${m.id}" aria-controls="m-${m.id}" aria-selected="${i === 0}" aria-label="${ROMAN[i]}. ${esc(m.title)}"><span class="numeral">${ROMAN[i]}</span><span class="t-title"> ${esc(m.title)}</span></button>`).join("\n        ");
const toggles = LANGS.map((l) => `<button type="button" aria-pressed="true" data-part="${l.id}">${l.name}</button>`).join("");

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vh: VH-Log in ${N} languages, side by side</title>
<meta name="description" content="${Ncap} implementations of VH-Log (${LANGS.map((l) => l.name).join(", ")}) that produce the same bytes, with their code compared where it matters.">
<meta name="color-scheme" content="light dark">
<meta property="og:title" content="vh: VH-Log in ${N} languages, side by side">
<meta property="og:description" content="${Ncap} implementations that produce the same bytes, checked against each other on every push.">
<meta property="og:image" content="https://brianorwhatever.github.io/vh/og.png">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<link rel="preload" href="fonts/newsreader-var.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="fonts/commit-mono-400.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="styles.css">
<script>document.documentElement.classList.add("js")</script>
</head>
<body>
<a class="skip" href="#score">Skip to the code</a>
<header class="masthead">
  <div class="title">
    <h1>vh</h1>
    <p class="line">${Ncap} implementations of VH&#8209;Log that produce the same&nbsp;bytes.</p>
  </div>
  <div class="intro">
    <p>${NAMES}, checked against each other and against <span class="nw">didwebvh-ts</span> on every push. Below: four algorithms that matter, in all ${N}, one beat at a time.</p>
    <a class="action" href="${REPO}">Source on GitHub</a>
  </div>
</header>

<main>
  <div class="score" id="score">
    <div class="controls">
      <div class="tabs" role="tablist" aria-label="Movements">
        ${tabs}
      </div>
      <div class="toggles" role="group" aria-label="Parts shown">${toggles}</div>
    </div>
    ${MOVEMENTS.map(movementPanel).join("\n    ")}
  </div>

  <section class="field" aria-labelledby="interop">
    <div class="field-inner">
      <div class="field-text">
        <h2 id="interop">Every producer, every resolver</h2>
        <p>Each implementation runs as a driver behind one small JSON Lines protocol. The harness feeds all ${N} the same vectors, then has each one resolve the logs every other one generated: ${pairings} pairings, ${logsPerPairing} files each.</p>
        <dl class="suites">
          ${suites}
        </dl>
        <p class="total"><span class="num">${fmt(perImplTotal)}</span> checks per implementation, <span class="num">${fmt(runTotal)}</span> per run.</p>
      </div>
      ${crossTable}
    </div>
  </section>

  <section class="parts" aria-labelledby="parts">
    <h2 id="parts">The ${N} parts</h2>
    <p class="section-lede">Non-blank lines of library code, without tests or the driver.</p>
    <ol class="part-list">
        ${partsList}
    </ol>
  </section>

  <section class="open" aria-labelledby="open">
    <h2 id="open">What the spec leaves open</h2>
    <div class="open-grid">
      <div>
        <p>Building it ${N} times turned up ${specNotes} notes on the spec. The first one: the worked example in <i>Generate Entry Hash</i> does not reproduce.</p>
        <figure class="hashes">
          <div><span class="label">The spec states</span><code><del>QmQ6FJ4fk2xheSSQoEjVpTgx9AQPKhJgtR9hn1nr4EeCrZ</del></code></div>
          <div><span class="label">All ${N} compute, and so does didwebvh-ts</span><code>QmXoHG2Z6Hg1kmryaRxcqgzF6nv2vgLZnYHvGirL9t2a8U</code></div>
        </figure>
        <p><a href="${REPO}/blob/${REF}/docs/spec-notes.md">All ${specNotes} spec notes</a></p>
      </div>
      <div>
        <p>Where the spec leaves a choice open, the <a href="${REPO}/blob/${REF}/docs/profile.md">interop profile</a> makes it once, for all ${N}:</p>
        <ul class="choices">
          <li>A proof names its key as <code>did:key:&lt;mk&gt;#&lt;mk&gt;</code>.</li>
          <li>A witness signs <code>{"versionId": …}</code>, as in did:webvh.</li>
          <li>Every proof on an entry must be valid and authorised, not just one.</li>
          <li>The first invalid entry ends the log. The valid prefix still resolves, with an <code>invalid-entries</code> warning.</li>
          <li>Failures carry one shared error code, found in one shared check order.</li>
        </ul>
      </div>
    </div>
  </section>

  <section class="add" aria-labelledby="add">
    <h2 id="add">Add a language</h2>
    <p class="section-lede">A ${NEXT} part is welcome. It joins the matrix, and the page, by passing the same tests as the other ${N}.</p>
    <ol class="steps">
      <li>
        <h3>Read the documents, not the code</h3>
        <p>Work from the <a href="${spec.repository}/tree/${spec.commit}">pinned spec</a>, the <a href="${REPO}/blob/${REF}/docs/profile.md">interop profile</a>, the <a href="${REPO}/blob/${REF}/docs/interop-protocol.md">driver protocol</a> and the shared <a href="${REPO}/tree/${REF}/vectors">vectors</a>. Zig, Common Lisp and Forth were built that way, so each is an independent check that the documents are enough. Note anything you had to guess.</p>
      </li>
      <li>
        <h3>Write a driver</h3>
        <p>One long-running process that reads a JSON request per line on stdin and writes a JSON response per line on stdout. Split on <code>\\n</code> only, parse numbers as doubles, and keep stdout for responses. It answers ${OPS.length} operations:</p>
        <p class="ops">${OPS.map((o) => `<code>${o}</code>`).join(" ")}</p>
      </li>
      <li>
        <h3>Register it</h3>
        <p>Add an entry to <a href="${REPO}/blob/${REF}/implementations.json"><code>implementations.json</code></a>: where it lives, how to build it, how to start the driver.</p>
        <pre tabindex="0" aria-label="implementations.json entry"><code>{
  "name": "ocaml",
  "cwd": "implementations/ocaml",
  "build": ["dune", "build"],
  "command": ["_build/default/bin/vh_log_driver.exe"]
}</code></pre>
      </li>
      <li>
        <h3>Run the harness until it is green</h3>
        <pre tabindex="0" aria-label="Harness commands"><code>node harness/run.ts --impl ocaml              <span class="c"># your driver alone</span>
node harness/run.ts                           <span class="c"># everyone, including cross</span>
node harness/run.ts --update-readme           <span class="c"># regenerate the matrix</span></code></pre>
        <p>Then give it a job in <a href="${REPO}/blob/${REF}/.github/workflows/interop.yml"><code>interop.yml</code></a> that runs its own tests, and add it to the interop job's toolchains.</p>
      </li>
      <li>
        <h3>Put it in the score</h3>
        <p>In <a href="${REPO}/blob/${REF}/site/build.mjs"><code>site/build.mjs</code></a>, add the language to <code>LANGS</code> and <code>PARTS</code>, then give each of the four movements a line range and the text of each beat. The build reads the code from your files and fails if a beat's text isn't found, so the page can't show code you don't have. Counts, the matrix and every "${N}" on the page update on their own.</p>
        <pre tabindex="0" aria-label="A part in site/build.mjs"><code>"ocaml": { ranges: [["ocaml/lib/proof.ml", 40, 43]],
  marks: [[1, "sha256 (canonicalize config)"],
          [2, "sha256 (canonicalize document)"],
          [3, "^"]] },</code></pre>
      </li>
    </ol>
  </section>
</main>

<footer class="run" aria-labelledby="run">
  <h2 id="run">Run it</h2>
  <pre tabindex="0" aria-label="Commands"><code>git clone ${REPO}
cd vh
node harness/run.ts                            <span class="c"># everything</span>
node harness/run.ts --impl rust --impl zig     <span class="c"># a subset</span>
node harness/run.ts --suite resolution --verbose</code></pre>
  <p>Node 24 runs the harness. Each driver also needs its own toolchain; the <a href="${REPO}/blob/${REF}#development">README lists them</a>.</p>
  <p class="colophon">VH-Log is <a href="${spec.rendered}">Stephen Curran's Verifiable History Log</a>, pinned here at <a class="nw" href="${spec.repository}/tree/${spec.commit}">swcurran/VH-Log@${spec.commit}</a>. MIT licence. <a href="${REPO}">github.com/brianorwhatever/vh</a></p>
</footer>
<script src="main.js" defer></script>
</body>
</html>
`;

fs.writeFileSync(path.join(SITE, "index.html"), html);
console.log(`wrote site/index.html (${MOVEMENTS.length} movements, ${perImplTotal} checks per implementation, ref ${REF})`);
