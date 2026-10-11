// The conductor: one movement at a time, its beats played through all language examples together.
const BEAT_MS = 2400;
const tabs = [...document.querySelectorAll('[role="tab"]')];
const panels = [...document.querySelectorAll(".movement")];
const score = document.getElementById("score");
const playback = document.getElementById("play-steps");
const reduce = matchMedia("(prefers-reduced-motion: reduce)");

let current = panels[0];
let beat = 1;
let timer = 0;
let pinned = true; // steps stay still until the reader opts into playback
let held = false; // hover or focus on a beat holds it while there
let onScreen = true;

function setBeat(n) {
  beat = n;
  current.dataset.beat = String(n);
  for (const b of current.querySelectorAll("[data-beat]")) b.setAttribute("aria-pressed", String(Number(b.dataset.beat) === n));
  for (const staff of current.querySelectorAll(".staff")) cue(staff, n);
  barline();
}

// Keep the full excerpt visible; highlighting never hides or scrolls code.
function cue(staff, n) {
  const el = staff.querySelector(".cue");
  const code = staff.querySelector(".code");
  const pre = staff.querySelector("pre");
  const mark = staff.querySelector(`mark[data-b="${n}"]`);
  if (!mark || staff.hidden) { el.classList.remove("on"); code.classList.remove("clipped"); return; }
  const y = mark.getBoundingClientRect().top - pre.getBoundingClientRect().top;
  el.textContent = String(n);
  el.style.setProperty("--cue-y", `${y + 2}px`);
  code.style.setProperty("--cue-y", `${y}px`);
  el.classList.add("on");
  const bounds = mark.getBoundingClientRect();
  const viewport = pre.getBoundingClientRect();
  code.classList.toggle("clipped", bounds.left < viewport.left || bounds.right > viewport.right);
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
  pinned = true;
  playback.textContent = "Play steps";
  held = false;
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
  b.addEventListener("click", () => { pinned = true; playback.textContent = "Play steps"; setBeat(n); schedule(); });
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

playback.addEventListener("click", () => {
  pinned = !pinned;
  playback.textContent = pinned ? "Play steps" : "Pause steps";
  schedule();
});
for (const pre of document.querySelectorAll(".staff pre")) {
  pre.addEventListener("scroll", () => cue(pre.closest(".staff"), beat));
}

new IntersectionObserver(([e]) => { onScreen = e.isIntersecting; schedule(); }).observe(score);
document.addEventListener("visibilitychange", schedule);
function motionPreference() {
  playback.hidden = reduce.matches;
  schedule();
}
reduce.addEventListener("change", motionPreference);
motionPreference();

addEventListener("resize", () => setBeat(beat));
document.fonts?.ready.then(() => setBeat(beat));
show(panels[0].dataset.movement);
