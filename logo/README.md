# attest — logo

A slip of paper with a torn edge, and the name set as a filename. The mark says *a record
someone handed you*; the leading dot says *a file you keep*. Nothing here is decorative — if
an element cannot be explained in those terms, it does not belong.

## Files

| File | Use |
|---|---|
| `banner.png` | Cover image: the lockup on a torn slip of paper. Used at the top of the repository README. The area below the teeth is transparent, so it reads as paper on a dark page and as a panel on a light one. |
| `lockup.svg` | The primary logo: mark plus wordmark. Use this wherever there is room. |
| `lockup-square-dot.svg` | Same lockup with the leading dot cut as a square instead of the typeface's round period. An alternate, not the default. |
| `mark.svg` | The mark alone, for sizes down to about 24 px. |
| `mark-small.svg` | The mark redrawn for small sizes: three teeth, one thicker line. Use below ~24 px. |
| `wordmark.svg` | The wordmark alone, already outlined. |
| `favicon.svg` | `mark-small.svg` under the name browsers look for. |
| `favicon-16.png`, `favicon-32.png` | Raster fallbacks, ink on transparent. |
| `apple-touch-icon-180.png` | Paper mark on an ink tile, opaque as Apple requires. |
| `lockup-ink.png`, `lockup-paper.png` | Raster lockups on transparent, for places that cannot take an SVG. |
| `social-preview-1280x640.png` | GitHub repository social preview (Settings → General → Social preview). |

Every SVG is a single colour and uses `fill="currentColor"`, so it inherits the colour of the
text around it. There is no light version and no dark version — there is one drawing, and it
takes the colour of wherever it is placed.

## Rules

**Clear space.** Keep free space around the logo equal to the height of the mark's torn teeth
(1/6 of the mark's height). Nothing else goes inside that.

**Minimum sizes.** The lockup stops working below about 90 px wide; use the mark alone under
that. `mark.svg` holds down to 24 px. Below 24 px use `mark-small.svg` — the two-line version
turns to mush, which is exactly what the small cut exists to avoid.

**Colour.** One colour, always. The reference pair is ink `#17191D` on paper `#F1F0ED`, and
either may be the background. Do not add a second colour, a gradient, or a shadow.

**Don't.** Do not re-space or re-draw the wordmark; do not set the name in another typeface and
call it the logo; do not rotate, outline, or fill the mark with anything; do not place the
lockup on a busy image.

## Typeface

The wordmark is **Courier Prime Bold**, designed by Alan Dague-Greene for John August and
published by Quote-Unquote Apps under the SIL Open Font License 1.1. The licence text is in
[`COURIER-PRIME-OFL.txt`](COURIER-PRIME-OFL.txt).

The glyphs in `lockup.svg` and `wordmark.svg` are **converted to outlines**, so the files carry
no font dependency and render identically everywhere. This is also why the typeface had to be
openly licensed: a system font's licence generally does not grant the right to turn its outlines
into a mark, and this repository is not the place to borrow something that was not lent.

## Regenerating

The assets are generated, not hand-drawn: the mark is defined by its path data above, and the
wordmark is cut from the font with `fontTools` (`SVGPathPen` over the glyph set, scaled so the
wordmark's x-height is 0.788 of the mark's ink height, with a gap of 1/5 of that height between
them). Keeping those two constants is what keeps the lockup consistent if it is ever recut.
