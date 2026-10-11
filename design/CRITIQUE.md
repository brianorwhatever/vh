# Critique

One critic (a fresh agent) for the whole job, scoring rendered PNGs against the web-designer rubric.

## Round 1

| # | Line | Score |
|---|---|---|
| 1 | Concept on the page | 3 |
| 2 | Not the category average | 4 |
| 3 | Not a slop face | 4 |
| 4 | First screen | 3 |
| 5 | Typography | 3 |
| 6 | Colour | 4 |
| 7 | Richness | 4 |
| 8 | Structure and rhythm | 4 |
| 9 | Craft | 3 |
| 10 | Responsive | 2 |
| 11 | Everyone's computer | 3 |
| 12 | Signature | 3 |
| 13 | Screenshot test | 3 |

Asks, all applied in round 2:
1. Phone code unwrapped, scrolled so the beat is in view, with an edge fade.
2. The beat reads as a beat: ink plus a magenta underline, a cue numeral in every stave's gutter (a bar line), and a conductor rule that fills over 2.4 s.
3. Phone tabs as numerals, beats as a vertical list, a smaller wordmark.
4. Unboxed language toggles; a hidden part is shown as tacet.
5. Matrix as a thin white grid with an italic diagonal; aligned stats; nowrap spec link.

Scan and matrix: no FAILs and no warns. Firefox and WebKit passes were skipped because the engines would not launch on this machine.

## Round 2

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R2 | 4 | 4 | 4 | 3 | 4 | 4 | 4 | 4 | 3 | 3 | 3 | 4 | 3 |

Asks applied in round 3: a phone reduction (signature plus the line being played), desktop tabs from 640px up, a bar line joining the cue numerals, WebKit running in the matrix, a claim line and a reference rule on the matrix.

## Round 3

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R3 | 4 | 4 | 4 | 3 | 4 | 4 | 4 | 4 | 3 | 3 | 4 | 4 | 4 |

Blocking defect: the sticky phone beat list overlapped the staves. Fixed in round 4, along with per-line scrolling, no auto-scroll from 640px up (a magenta edge tick marks a clipped beat), and the GitHub action as a link on phones.
Declined: the 200ms height animation on the phone reduction (it would mean measuring layout each beat), the "whole function" link (each stave already links file:line), and trimming the indent to 2ch (indentation is syntax in Python and Elixir).

## Round 4 (final)

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R4 | 4 | 4 | 4 | 4 | 4 | 4 | 4 | 4 | 3 | 4 | 4 | 4 | 4 |

Done by the stop rule: 12 of 13 at 4 or above, none below 3, and no FAILs.

Fixed after the last round, not rescored:
- Collapsed runs on the phone render as one "⋯" row, never a blank row, and there is no leading marker.
- The kept context line is the declaration (`fn`/`def`/`defun`…), not the first line of code.
- The left fade is opaque for 18px, and a scrolled beat starts after it.
- Common Lisp (added upstream mid-job) is a ninth part in every movement. All counts and copy now come from the README and the language list.

Unverified: Firefox (Playwright's Firefox crashes at launch on this macOS beta).
