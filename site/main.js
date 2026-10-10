// The conductor: one movement at a time, its beats played through all eight parts together.
const BEAT_MS = 2400;
const tabs = [...document.querySelectorAll('[role="tab"]')];
const panels = [...document.querySelectorAll(".movement")];
const score = document.getElementById("score");
const reduce = matchMedia("(prefers-reduced-motion: reduce)");

let current = panels[0];
let beat = 1;
let timer = 0;
let pinned = false; // a beat the reader clicked stays until the movement changes
let held = false; // hover or focus on a beat holds it while there
let onScreen = true;

const narrow = matchMedia("(max-width: 639px)");

function setBeat(n) {
  beat = n;
  current.dataset.beat = String(n);
  for (const b of current.querySelectorAll("[data-beat]")) b.setAttribute("aria-pressed", String(Number(b.dataset.beat) === n));
  for (const staff of current.querySelectorAll(".staff")) cue(staff, n);
  barline();
}

// On a phone each stave is reduced to its signature and the lines holding the beat.
function reduceStaff(staff, n) {
  let seenKept = false;
  let inGap = false;
  for (const ln of staff.querySelectorAll(".ln")) {
    const keep = !narrow.matches || ln.hasAttribute("data-sig") || (ln.dataset.has || "").split(" ").includes(String(n));
    // The first hidden line after a kept one stands for the whole run as "⋯".
    const gapline = !keep && seenKept && !inGap;
    ln.classList.toggle("cut", !keep && !gapline);
    ln.classList.toggle("gapline", gapline);
    if (keep) { seenKept = true; inGap = false; } else if (gapline) inGap = true;
  }
  // A run of hidden lines at the end needs no marker.
  const lines = [...staff.querySelectorAll(".ln")];
  for (let i = lines.length - 1; i >= 0 && !lines[i].matches(":not(.cut):not(.gapline)"); i--) {
    lines[i].classList.remove("gapline");
    if (narrow.matches) lines[i].classList.add("cut");
  }
}

// Moves a stave's cue numeral to the line its beat is on. On a phone the line
// holding the beat scrolls on its own, only if the beat runs past its right
// edge. Wider staves never scroll by themselves; a tick marks a clipped beat.
function cue(staff, n) {
  const el = staff.querySelector(".cue");
  const code = staff.querySelector(".code");
  const pre = staff.querySelector("pre");
  reduceStaff(staff, n);
  const mark = staff.querySelector(`mark[data-b="${n}"]`);
  if (!mark || staff.hidden) { el.classList.remove("on"); code.classList.remove("clipped"); return; }
  const y = mark.getBoundingClientRect().top - pre.getBoundingClientRect().top;
  el.textContent = String(n);
  el.style.setProperty("--cue-y", `${y + 2}px`);
  code.style.setProperty("--cue-y", `${y}px`);
  el.classList.add("on");
  for (const ln of staff.querySelectorAll(".ln.scrolled")) { ln.classList.remove("scrolled"); ln.scrollLeft = 0; }
  if (narrow.matches) {
    const line = mark.closest(".ln");
    const left = mark.offsetLeft + mark.offsetWidth > line.clientWidth - 24 ? Math.max(0, mark.offsetLeft - 30) : 0;
    line.classList.toggle("scrolled", left > 0);
    line.scrollLeft = left;
    code.classList.remove("clipped");
  } else {
    code.classList.toggle("clipped", mark.offsetLeft + mark.offsetWidth > pre.scrollLeft + pre.clientWidth);
  }
}

// Joins the visible cue numerals with one hairline, drawn top to bottom.
function barline() {
  const system = current.querySelector(".system");
  let bar = system.querySelector(".barline");
  if (!bar) { bar = document.createElement("span"); bar.className = "barline"; bar.setAttribute("aria-hidden", "true"); system.append(bar); }
  const box = system.getBoundingClientRect();
  const ys = [];
  let x = 0;
  for (const staff of current.querySelectorAll(".staff:not([hidden])")) {
    const mark = staff.querySelector(`mark[data-b="${beat}"]`);
    const c = staff.querySelector(".cue");
    if (!mark) continue;
    const r = mark.getBoundingClientRect();
    ys.push(r.top + r.height / 2 - box.top);
    x = c.getBoundingClientRect().left + c.offsetWidth / 2 - box.left;
  }
  if (ys.length < 2) { bar.style.setProperty("--bar-h", "0px"); return; }
  bar.style.setProperty("--bar-x", `${x}px`);
  bar.style.setProperty("--bar-y", `${ys[0] + 12}px`);
  bar.style.setProperty("--bar-h", `${ys.at(-1) - ys[0] - 24}px`);
  bar.classList.remove("draw");
  void bar.offsetWidth;
  bar.classList.add("draw");
}

// Restarts the conductor's rule under the active beat while the score plays.
function conduct(playing) {
  current.classList.remove("playing");
  if (!playing) return;
  void current.offsetWidth;
  current.classList.add("playing");
}

function schedule() {
  clearTimeout(timer);
  const playing = !(reduce.matches || pinned || held || !onScreen || document.hidden);
  conduct(playing);
  if (!playing) return;
  timer = setTimeout(() => {
    setBeat((beat % current.querySelectorAll("[data-beat]").length) + 1);
    schedule();
  }, BEAT_MS);
}

function show(id, focus = false) {
  for (const t of tabs) {
    const on = t.getAttribute("aria-controls") === `m-${id}`;
    t.setAttribute("aria-selected", String(on));
    t.tabIndex = on ? 0 : -1;
    if (on && focus) t.focus();
  }
  for (const p of panels) { p.hidden = p.dataset.movement !== id; p.style.setProperty("--beat-ms", `${BEAT_MS}ms`); }
  current = panels.find((p) => p.dataset.movement === id);
  pinned = false;
  setBeat(1);
  schedule();
}

tabs.forEach((t, i) => {
  t.addEventListener("click", () => show(t.getAttribute("aria-controls").slice(2)));
  t.addEventListener("keydown", (e) => {
    const step = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
    if (!step) return;
    e.preventDefault();
    show(tabs[(i + step + tabs.length) % tabs.length].getAttribute("aria-controls").slice(2), true);
  });
});

for (const b of document.querySelectorAll("[data-beat]")) {
  const n = Number(b.dataset.beat);
  b.addEventListener("click", () => { pinned = true; setBeat(n); schedule(); });
  for (const ev of ["pointerenter", "focus"]) b.addEventListener(ev, () => { held = true; setBeat(n); schedule(); });
  for (const ev of ["pointerleave", "blur"]) b.addEventListener(ev, () => { held = false; schedule(); });
}

// Parts: hide or show a language in every movement. At least one part keeps playing.
const toggles = [...document.querySelectorAll("[data-part]")];
for (const b of toggles) {
  b.addEventListener("click", () => {
    const on = b.getAttribute("aria-pressed") === "true";
    if (on && toggles.filter((x) => x.getAttribute("aria-pressed") === "true").length === 1) return;
    b.setAttribute("aria-pressed", String(!on));
    for (const s of document.querySelectorAll(`.staff[data-lang="${b.dataset.part}"]`)) s.hidden = on;
    setBeat(beat);
  });
}

new IntersectionObserver(([e]) => { onScreen = e.isIntersecting; schedule(); }).observe(score);
document.addEventListener("visibilitychange", schedule);
reduce.addEventListener("change", schedule);

addEventListener("resize", () => setBeat(beat));
narrow.addEventListener("change", () => setBeat(beat));
document.fonts?.ready.then(() => setBeat(beat));
show(panels[0].dataset.movement);
