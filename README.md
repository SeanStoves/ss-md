# ss-md

> **Provenance.** I wrote this code for my own site ([seanstoves.com](https://seanstoves.com)).
> [Claude Code](https://claude.com/claude-code) did the work of ripping it out of the app,
> decoupling it, and cleaning it up for distribution — I reviewed every line, but that's the
> honest origin story. Either way: read it before you trust it. You should do that with any
> dependency you didn't write.

A zero-dependency markdown subset compiler and multi-language syntax highlighter,
built to sit directly on an XSS boundary. No parser dependency, no `marked`, no
Prism, no DOMPurify — nothing to track CVEs for. Two small hand-rolled tokenizers
that escape everything and only ever emit tags they build themselves.

If you render user-authored or content-repo markdown straight into a page, the usual
stack is a parser plus a sanitizer plus their combined attack surface. This trades
all of that for a deliberately tiny compiler whose entire XSS surface collapses to a
single question — *is the URL in this link/image safe?* — which `safeUrl` owns.

## Security scan

Last run **2026-06-14** against this repo's source. Every row is reproducible — re-run it yourself,
that's the whole pitch.

| Area | What I tested | Result / posture |
|---|---|---|
| Supply chain | `npm audit` + retire.js 5.4.3; runtime-dependency count | **0 vulnerabilities, 0 runtime deps** — there's no transitive tree to track |
| Secrets | secretlint (recommend preset, validated against a planted token) + manual PEM / `.env` / credential sweep | **clean** — no keys, no `.env`, no hardcoded tokens |
| XSS (the boundary) | 54 regression payloads: `javascript:` / `data:` schemes, entity-encoding, tag breakout, nested-list injection | **neutralized** — every text run escaped, raw HTML never emitted, URLs allowlisted by `safeUrl` |
| Highlighter | `stripSpans(out) === escHtml(code)` across all 8 languages + a 5000-input seeded fuzz | **invariant holds, 0 raw-angle leaks** — it only wraps already-escaped text |
| ReDoS / DoS | 256 KB pathological inputs per language; bracket-bomb, nested-list & blockquote depth bombs | **linear time** — input capped at 256 KB, recursion depth-capped, bounded quantifiers |
| Adversarial review | 4 multi-agent passes: XSS breakout · ReDoS/DoS · strip-spans invariant · integration | **0 unresolved findings** |
| License | — | **MIT**, zero deps → no transitive license obligations |

A zero-dependency library collapses the whole supply-chain surface down to *one* thing: this code. Which
is exactly why the recommended install is **Option B — vendor it and read it.**

## Security model

The whole thing is built on three guarantees:

- **Escape everything.** Every text run goes through HTML escaping before it lands in
  the output. The compiler never passes raw HTML through and only emits tags it
  constructs itself. A pasted `<script>` or `<img onerror=...>` renders as inert
  escaped text, not a live element.
- **`safeUrl` is an allowlist, not a blocklist.** Relative and anchor URLs pass
  untouched (no scheme is possible). Anything with a scheme is decoded (so
  `javascript&#58;` can't hide its colon), stripped of control/whitespace chars (so
  `java\tscript:` can't split the token), lowercased, then tested against exactly
  three permitted schemes: `http`, `https`, `mailto`. Protocol-relative `//host` and
  backslash-folded `/\host` are rejected — browsers resolve those to a foreign
  origin. Everything else returns `null` and the link renders as inert escaped text.
- **The highlighter invariant: `stripSpans(out) === escHtml(code)`.** The highlighter
  only *adds* `<span class="tok-...">` wrappers around already-escaped text. Strip the
  spans back off and you get the plain-escaped code byte-for-byte. If that holds for
  every input — and the test suite fuzzes it across thousands of hostile inputs in
  every language — then no byte of code can ever escape un-escaped. There's no
  injection surface in the highlighter at all.

Both tokenizers are linear-time and ReDoS-resistant: sticky/anchored regexes only,
bounded quantifiers, no catastrophic backtracking. Inputs are capped (256 KB), and
recursion (nested lists, blockquotes) is depth-capped so an indentation or `>`-run
bomb can't blow the stack or stall the loop. The test suites pin all of this.

## Supported languages

The highlighter tokenizes these; everything else falls back to plain escaped text:

- TypeScript / JavaScript (`ts`, `tsx`, `js`, `jsx`, `mjs`, `cjs`)
- JSON / JSONC / JSON5
- C# (`cs`, `csharp`, `c#`, `dotnet`)
- Python (`py`, `python`)
- Terraform / HCL (`hcl`, `tf`, `terraform`)
- YAML (`yaml`, `yml`)
- Dockerfile (`dockerfile`, `docker`)
- Helm / Go templates (`helm`, `gotmpl`)

## Install — pick your supply-chain tolerance

**A. From npm** — published with signed provenance, zero runtime deps:

```sh
npm install ss-md
```

(React is an optional peer dependency, only needed if you mount the `ss-md/react` island.)

> **Real talk: I'd skip this and vendor it (Option B).** Yes, it's on npm for convenience — but
> even a zero-dependency package is still a supply-chain link you're choosing to trust: a future
> release, a hijacked account, a typosquatted name one fat-finger away. Code this small is code you
> can read in one sitting and *own outright*. Cloning the files in is the move I'd actually make.

**B. Vendor it (zero dependencies, including this one).** The compiler and highlighter
are two self-contained files that import nothing. Copy them into your project and you
depend on no registry at all — which, for code whose entire job is to sit on an XSS
boundary, is the honest move: read it once, own it, no transitive deps to trust.

```sh
# the whole library is these two files (plus the optional React island + CSS)
cp path/to/ss-md/src/markdown.ts   src/lib/markdown.ts
cp path/to/ss-md/src/highlight.ts  src/lib/highlight.ts
# optional extras:
cp path/to/ss-md/src/react/PostBody.tsx  src/components/PostBody.tsx
cp -r path/to/ss-md/styles               src/styles/markdown
```

`markdown.ts` imports `./highlight.ts` and nothing else; `highlight.ts` imports nothing.
Drop them in, import `renderMarkdown` / `highlight`, done. This is the recommended path
if you don't want a dependency you have to track CVEs for — the point of the library is
that there's nothing to track.

## API

### `renderMarkdown(input: string): string`

Compiles a markdown subset (headings, paragraphs, bold/italic, inline + fenced code,
links, images, ul/ol with nesting, blockquotes, hr) to escaped HTML. Fenced code
blocks are run through the highlighter by language tag.

```ts
import { renderMarkdown } from 'ss-md';

const html = renderMarkdown('# Hi\n\nSome **bold** and a [link](https://example.com).');
```

### `safeUrl(raw: string): string | null`

The URL allowlist gate. Returns the URL as entered if it's safe to put in an `href`
or `src`, or `null` if its scheme isn't permitted. Used internally by
`renderMarkdown`; exported because it's useful on its own anywhere you take a URL
from untrusted input.

```ts
import { safeUrl } from 'ss-md';

safeUrl('https://example.com');     // 'https://example.com'
safeUrl('/blog/post');              // '/blog/post'
safeUrl('javascript:alert(1)');     // null
safeUrl('//evil.com');              // null
```

### `highlight(code: string, lang: string): string`

Standalone syntax highlighter. Returns escaped code wrapped in `<span class="tok-*">`
tokens (`tok-keyword`, `tok-string`, `tok-number`, `tok-comment`). Unknown languages
return plain escaped text.

```ts
import { highlight } from 'ss-md';

highlight('const x = 1;', 'ts');
```

### `PostBody` (optional React layer)

```tsx
import { PostBody } from 'ss-md/react';
import { renderMarkdown } from 'ss-md';

export default function Post({ markdown }: { markdown: string }) {
    return <PostBody html={renderMarkdown(markdown)} />;
}
```

`PostBody` is a client island over the compiled HTML. It only attaches behaviour —
a copy button per code block, click-to-zoom on images, and a click-to-play poster for
GIFs — to output that was already escaped at render time. It decorates, it never
re-introduces raw HTML.

## CSS

The compiler emits **structure only**. It does not ship a stylesheet inline; you bring
the styling. Two ways:

1. **Use the bundled sheets.** They're the Tailwind neutral/blue/violet/green palette
   baked to concrete hex, scoped under `.post-content`:

   ```ts
   import 'ss-md/styles/prose.css';   // prose + .tok-* token colors
   import 'ss-md/styles/react.css';   // PostBody decorations (only if you use the island)
   import 'ss-md/styles/tokens.css';  // optional: the named palette as :root vars to override
   ```

   Or wrap your rendered output in a `.post-content` container and link the sheets
   directly (see `examples/browser.html`).

2. **Bring your own.** Style `.post-content` and the `.tok-comment` / `.tok-keyword` /
   `.tok-string` / `.tok-number` classes however you like. The token class names are a
   closed set, so a handful of rules covers all eight languages.

The `.gif` → `gif-player` convention (an animated GIF gets a marker class so it can be
frozen on frame 0 and gated behind a click) is **only** meaningful for the optional
React island — the compiler just tags it; `PostBody` does the canvas work. If you're
using the bare compiler, that class is inert and harmless.

## Tests

```sh
npm test
```

Runs `tests/markdown-xss.ts` (the XSS regression suite for the compiler and `safeUrl`)
and `tests/highlight.ts` (the strip-spans invariant, per-language fuzzing, and
ReDoS/timing guards). These are the load-bearing tests — the one place a silent
regression equals an XSS hole — so they run on every change.

## Contributing

Fork it, branch, open a PR. Keep it boring on purpose:

- **Zero runtime dependencies stays zero.** A PR that adds one to the production tree won't land — the
  entire value here is that there's nothing to trust but the code in front of you.
- **The tests are the contract.** `npm test` (54 XSS + 24 highlighter cases) stays green. This sits on an
  XSS boundary, so a silent regression *is* a vulnerability — if you touch the compiler or the highlighter,
  add a test that proves your change is safe *before* you change the code.
- **Don't move the invariant.** Strip the spans and you still get `escHtml(code)` back; every text run is
  escaped; `safeUrl` stays an allowlist. If a change touches the XSS surface, say so loudly in the PR.
- **Match the voice.** Comment the hard stuff, leave the obvious alone, no marketing words.

Found a security issue? Don't open a public issue — use GitHub's private **"Report a vulnerability"** (the
repo's Security tab), or email **sean@seanstoves.com**.

## License

MIT © 2026 Sean Stoves
