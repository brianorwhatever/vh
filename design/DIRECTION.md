# vh presentation page: direction

## Brief (self-authored)

- **What:** a one-page GitHub Pages site for this repository: eight
  interoperable implementations of VH-Log plus the harness that checks them
  against each other.
- **For:** people implementing or evaluating did:vh / did:webvh / VH-Log
  (the spec editor, DIF implementers, wallet and service builders picking a
  library).
- **The one job:** in ten seconds, see that the same algorithm is written
  eight times and agrees, then read the code side by side where it matters.
  Action: go to the source.
- **Feel:** exact, plural, convincing.
- **Exists:** the `VH` icon (magenta `#c026d3`), real code, real vectors,
  the README's interop matrix, spec notes. No photos. No image generation.

## Category default refused

Spec / crypto-library pages: a docs theme (Docusaurus, mkdocs-material) or a
dark dev-tool landing page with Inter + JetBrains Mono, tabbed code blocks in
rounded cards, a gradient hero, a feature grid of "Fast / Secure / Tested".
Category colours: navy and teal for trust, green ticks. Slop faces this brief
falls into naturally: the Dark Dev Tool (4) and the Launch Page (2).

## Three concepts

- **A. vh is an orchestral score** (printed matter). Eight staves, one
  phrase: each language is a part, each important function is a bar, and the
  page conducts the same step through all eight at once.
  Light cool score-paper ground, Newsreader + Commit Mono, richness = the
  real code (data), magenta, document/tool grammar, kinetic highlight.
- **B. vh is a round-robin crosstable** (play). Every implementation plays
  every other. Magenta colour field, Big Shoulders Display, the 8×8 table as
  the image, poster grammar, cells filling in turn.
- **C. vh is a tray of drill cores** (nature). Eight cores from eight sites
  with the same strata. Dark slate, Martian Mono, drawn strata, teal,
  scroll-story, bands settling.

**Won: A, with B's colour field merged in** for the interop section. A is
the only one where the first screen *is* the thing the user asked for (code
compared where it matters) and the metaphor organises it: parts, movements,
beats. B lost because the matrix is strong evidence but says nothing about
the code; it lives on as section 2. C lost because the strata are abstract
bands that needed a caption to mean anything; the swap test fails (any
"layers" product could use it).

History: `site|printed|light|serif|pink|data|tool-first`, clear.

## Tokens

Colour (OKLCH, in `site/styles.css`):

| Role | Light | Dark | Source |
|---|---|---|---|
| ground | `oklch(98.6% .004 290)` | `oklch(19% .02 310)` | engraved score paper, cool not cream / a dark concert hall |
| ink | `oklch(21% .02 300)` | `oklch(93% .01 300)` | engraving ink |
| ink-2 | `oklch(45% .02 300)` | `oklch(74% .02 300)` | performance directions |
| rule | `oklch(86% .01 300)` | `oklch(34% .02 300)` | staff lines |
| accent | `oklch(50% .22 325)` | `oklch(76% .16 325)` | the repo's VH icon magenta; one job: *the step being played now* (and links) |
| hl | `oklch(94% .05 325)` | `oklch(32% .09 325)` | the highlight under the current step |
| field | `oklch(46% .21 325)` | same | colour field of section 2, the icon colour deepened for white text |

Type: **Newsreader** (variable, with italics), because scores set titling,
instrument names and directions in a book serif with italics, and its optical
sizes hold at 15px and 120px. **Commit Mono**, because code must read as
code at 13–14px and it is neutral without being the default JetBrains/Geist
look. Scale: display clamp(4.5rem→9rem), h2 clamp(2rem→3.25rem), h3 1.375rem,
body 1.125rem, small .9375rem, meta .8125rem, code .875rem.

Space 4/8/12/16/24/40/64/104. Radius: 3px marks only; no boxes. Grid: score
system at full width (max 1440), text at 65ch.

## Richness

The real code from the repository, extracted at build time by line range,
set as a score. No illustration. The second section is a colour field with
the real interop matrix parsed from the README.

## Grammar (tool-first)

1. **First screen: the score.** "What is this and is it real?" Name, one
   line, the four movements, all eight parts playing movement I.
2. **Every producer, every resolver.** "How do I know they agree?" The
   matrix on a magenta field.
3. **The parts.** "Which one do I use?" Eight languages, why each exists,
   source size.
4. **What the spec leaves open.** "Is this faithful to VH-Log?" The
   entry-hash example that doesn't reproduce; the profile's choices.
5. **Run it.** Commands, pinned spec, licence, links.

## Signature: the conductor's beat

- **Trigger:** page load, and each movement change.
- **Frames:** each movement has 3–4 beats (e.g. entry hash: drop proof → set
  versionId → canonicalise → hash). On each beat the matching span in all
  eight staves takes the magenta highlight together, and the beat in the
  legend underneath lights. 2.4 s per beat, 280 ms ease-out colour change.
- **Interaction:** hover or focus a beat to hold it; click a movement to
  change; the beat pauses off-screen and when the tab is hidden.
- **Reduced motion:** no auto-advance; beat 1 shown, beats are buttons.
- **No JS:** every beat's spans shown highlighted at once.

## Voice

Talks like the README: plain, exact, numbers with their source, no
adjectives, no em dashes.

## Content

- Title: `vh` · line: "Eight implementations of VH-Log that produce the same
  bytes." · sub: "TypeScript, Rust, Python, Elixir, Go, Swift, Kotlin and Zig,
  checked against each other and against didwebvh-ts on every push." · action:
  "Source on GitHub".
- Movements: I The signing input (eddsa-jcs-2022), II The entry hash,
  III Verifying the SCID, IV Pre-rotation. Beats as in `site/build.mjs`.
- Section 2: "Every producer, every resolver", the matrix, 299 checks per
  implementation, 2,392 per run (parsed).
- Section 3: the eight parts, from the README notes, with source line counts.
- Section 4: spec note 1 with both hashes; four profile choices.
- Section 5: `node harness/run.ts`, toolchains, pinned `swcurran/VH-Log@f2f9fda`, MIT.
