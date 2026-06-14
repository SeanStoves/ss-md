import { highlight } from '../src/highlight.ts';

/*
 * The highlighter sits on the markdown XSS boundary: it turns a code block into
 * html. The core guarantee is that it only ADDS span wrappers — strip them and
 * you get the plain-escaped code back. If that holds for every input, no byte of
 * the code ever escapes un-escaped, so there's no injection surface.
 */

let pass = 0, fail = 0;
function check(name: string, fn: () => void) {
    try { fn(); console.log(`ok - ${name}`); pass++; }
    catch (e) { console.log(`FAIL - ${name}: ${(e as Error).message}`); fail++; }
}
function assert(cond: boolean, msg: string) { if (!cond) throw new Error(msg); }

// reference escape, independent of the highlighter's own copy
const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ESC[c]);
const stripSpans = (s: string) => s.replace(/<span class="tok-[a-z]+">/g, '').replace(/<\/span>/g, '');

// THE invariant: highlight only wraps, never changes the escaped text
const INPUTS = [
    "const x = 1;",
    "import { seal } from '@/lib/crypto';",
    "// a comment with </script> and <b> inside",
    "/* block\n with <img src=x onerror=alert(1)> */",
    "const t = `hello ${name} <not a tag>`;",
    "</code></pre><script>alert(document.cookie)</script>",
    "const s = 'it\\'s \"quoted\" & <escaped>';",
    "const n = 0xFF + 60_000 + 3.14e10;",
    'const a = "unterminated string with <script>',
    "/* unterminated block comment <script>",
    "x < y && a > b ? '<' : '>'",
    "// trailing\nconst π = '🔑 unicode <x>';",
    "",
    "`",
    "'''",
    "//",
];

check('strip-spans equals escHtml for every input', () => {
    for (const inp of INPUTS) {
        const got = stripSpans(highlight(inp, 'ts'));
        assert(got === esc(inp), `invariant broke on ${JSON.stringify(inp)}\n  got:  ${got}\n  want: ${esc(inp)}`);
    }
});

check('no raw < or > survives in highlighted output', () => {
    for (const inp of INPUTS) {
        const out = highlight(inp, 'ts');
        // the only < we permit is the span tags we emit ourselves
        const withoutOurTags = out.replace(/<span class="tok-[a-z]+">/g, '').replace(/<\/span>/g, '');
        assert(!/[<>]/.test(withoutOurTags), `raw angle bracket leaked for ${JSON.stringify(inp)}: ${withoutOurTags}`);
    }
});

check('script payload renders inert', () => {
    const out = highlight('</code></pre><script>alert(1)</script>', 'ts');
    assert(!out.includes('<script'), 'raw <script leaked');
    assert(!out.includes('</code>'), 'raw </code> leaked');
    assert(out.includes('&lt;script&gt;'), 'payload not escaped');
});

check('keywords / strings / numbers get spanned', () => {
    const out = highlight("const x = 'hi'; let n = 42;", 'ts');
    assert(out.includes('<span class="tok-keyword">const</span>'), 'const not a keyword');
    assert(out.includes('<span class="tok-keyword">let</span>'), 'let not a keyword');
    assert(out.includes('<span class="tok-string">&#39;hi&#39;</span>'), 'string not spanned/escaped');
    assert(out.includes('<span class="tok-number">42</span>'), 'number not spanned');
    assert(!out.includes('tok-keyword">x<'), 'identifier x wrongly flagged as keyword');
});

check('unknown language falls back to plain escape (no spans)', () => {
    for (const lang of ['bash', 'text', '', 'rust', 'go', 'sql']) {
        const out = highlight('<b>const x = 1</b>', lang);
        assert(out === esc('<b>const x = 1</b>'), `lang ${lang} should be plain-escaped, got ${out}`);
    }
});

// --- json tokenizer ---
const JSON_INPUTS = [
    '{"name": "next", "v": 16, "ok": true, "n": null}',
    '{\n  "url": "https://x.com/a?b=1",\n  "neg": -3.14e10\n}',
    '{"x": "</code></pre><script>alert(1)</script>"}',
    '{"k": "a \\" quote & <tag>"}',
    '// jsonc comment <script>\n{"a": /* inline */ 1}',
    '{"weird": "\\u0041 <b>"}',
    '[]',
    '{',
    '"dangling',
];
check('json strip-spans equals escHtml (no byte escapes un-escaped)', () => {
    for (const inp of JSON_INPUTS) {
        const got = stripSpans(highlight(inp, 'json'));
        assert(got === esc(inp), `json invariant broke on ${JSON.stringify(inp)}\n  got:  ${got}\n  want: ${esc(inp)}`);
    }
});
check('json script payload renders inert', () => {
    const out = highlight('{"x": "</script><script>alert(1)</script>"}', 'json');
    assert(!out.includes('<script'), 'raw <script leaked from json');
    assert(out.includes('&lt;script&gt;'), 'json payload not escaped');
});
check('json keys, values, numbers, literals get the right spans', () => {
    const out = highlight('{"name": "next", "v": 16, "ok": true}', 'json');
    assert(out.includes('<span class="tok-keyword">&quot;name&quot;</span>'), 'key not flagged as keyword');
    assert(out.includes('<span class="tok-string">&quot;next&quot;</span>'), 'value not a string');
    assert(out.includes('<span class="tok-number">16</span>'), 'number not spanned');
    assert(out.includes('<span class="tok-keyword">true</span>'), 'literal true not spanned');
});

// --- c# tokenizer ---
const CS_INPUTS = [
    'public class Foo { void Bar() { return; } }',
    'var s = "hello \\"world\\" & <tag>";',
    'var path = @"C:\\dir\\file & <x>";',
    'var x = $"interp {y} <b>";',
    'int n = 0xFF + 1_000 + 3.14f; // comment </script>',
    "/* block <script> */ char c = 'x';",
    'string s = "</code></pre><script>alert(1)</script>";',
];
check('c# strip-spans equals escHtml', () => {
    for (const inp of CS_INPUTS) {
        const got = stripSpans(highlight(inp, 'csharp'));
        assert(got === esc(inp), `c# invariant broke on ${JSON.stringify(inp)}\n  got:  ${got}`);
    }
});
check('c# keywords/strings/numbers spanned', () => {
    const out = highlight('public int x = 42; var s = "hi";', 'csharp');
    assert(out.includes('<span class="tok-keyword">public</span>'), 'public not keyword');
    assert(out.includes('<span class="tok-keyword">int</span>'), 'int not keyword');
    assert(out.includes('<span class="tok-number">42</span>'), '42 not number');
    assert(out.includes('<span class="tok-string">&quot;hi&quot;</span>'), 'string not spanned');
});

// --- python tokenizer ---
const PY_INPUTS = [
    'def f(x):\n    return x + 1  # comment <script>',
    's = "hello \\"world\\" & <tag>"',
    "t = '''triple\nquoted <b>\n'''",
    'r = r"raw\\path <x>"',
    'g = f"interp {x} <b>"',
    'n = 0xFF + 1_000 + 3.14j',
    'x = "</code></pre><script>alert(1)</script>"',
    'if True and None: pass',
];
check('python strip-spans equals escHtml', () => {
    for (const inp of PY_INPUTS) {
        const got = stripSpans(highlight(inp, 'python'));
        assert(got === esc(inp), `python invariant broke on ${JSON.stringify(inp)}\n  got:  ${got}`);
    }
});
check('python keywords/strings/numbers/comments spanned', () => {
    const out = highlight('def f(): return 42  # x\ns = "hi"', 'python');
    assert(out.includes('<span class="tok-keyword">def</span>'), 'def not keyword');
    assert(out.includes('<span class="tok-keyword">return</span>'), 'return not keyword');
    assert(out.includes('<span class="tok-number">42</span>'), '42 not number');
    assert(out.includes('<span class="tok-comment"># x</span>'), 'comment not spanned');
    assert(out.includes('<span class="tok-string">&quot;hi&quot;</span>'), 'string not spanned');
});

// --- terraform / hcl tokenizer ---
const HCL_INPUTS = [
    'resource "aws_s3_bucket" "b" {\n  bucket = "my-bucket"\n}',
    'variable "region" { default = "us-east-1" } # <script>',
    'count = var.enabled ? 1 : 0  // <b>inline</b>',
    '/* block <script> */ locals { x = 0xFF }',
    'tags = { Name = "</code></pre><script>alert(1)</script>" }',
    'data "aws_ami" "x" { most_recent = true }',
];
check('terraform strip-spans equals escHtml', () => {
    for (const inp of HCL_INPUTS) {
        const got = stripSpans(highlight(inp, 'terraform'));
        assert(got === esc(inp), `hcl invariant broke on ${JSON.stringify(inp)}\n  got:  ${got}`);
    }
});
check('terraform keywords/strings/numbers spanned', () => {
    const out = highlight('resource "x" "y" { count = 2 }', 'terraform');
    assert(out.includes('<span class="tok-keyword">resource</span>'), 'resource not keyword');
    assert(out.includes('<span class="tok-keyword">count</span>'), 'count not keyword');
    assert(out.includes('<span class="tok-string">&quot;x&quot;</span>'), 'string not spanned');
    assert(out.includes('<span class="tok-number">2</span>'), '2 not number');
});

// --- yaml tokenizer (github actions) ---
const YAML_INPUTS = [
    'name: CI\non: [push]',
    'jobs:\n  build:\n    runs-on: ubuntu-latest',
    'steps:\n  - uses: actions/checkout@v4\n  - run: echo "hi & <x>"',
    'env:\n  KEY: "</code></pre><script>alert(1)</script>"',
    '# a comment with <script>\nkey: value',
    'flag: true\ncount: 42\nempty: null',
    'anchor: &a value\nref: *a',
    "quoted: 'single & <tag>'",
];
check('yaml strip-spans equals escHtml', () => {
    for (const inp of YAML_INPUTS) {
        const got = stripSpans(highlight(inp, 'yaml'));
        assert(got === esc(inp), `yaml invariant broke on ${JSON.stringify(inp)}\n  got:  ${got}`);
    }
});
check('yaml keys/strings/comments/literals spanned', () => {
    const out = highlight('name: CI  # x\nflag: true\nn: 42\ns: "hi"', 'yaml');
    assert(out.includes('<span class="tok-keyword">name</span>'), 'key name not spanned');
    assert(out.includes('<span class="tok-comment"># x</span>'), 'comment not spanned');
    assert(out.includes('<span class="tok-keyword">true</span>'), 'true literal not spanned');
    assert(out.includes('<span class="tok-number">42</span>'), '42 not spanned');
    assert(out.includes('<span class="tok-string">&quot;hi&quot;</span>'), 'string not spanned');
});
check('yaml: dotted versions colour as numbers, alnum scalars do not', () => {
    assert(highlight('v: 1.2.3', 'yaml').includes('<span class="tok-number">1.2.3</span>'), 'semver not a number');
    assert(highlight('image: app:1.21.6', 'yaml').includes('<span class="tok-number">1.21.6</span>'), 'image-tag version not a number');
    assert(!highlight('size: 8gb', 'yaml').includes('tok-number'), '8gb wrongly flagged as a number');
});

// --- dockerfile tokenizer ---
const DOCKER_INPUTS = [
    'FROM node:24-alpine\nWORKDIR /app',
    'RUN echo "hi & <x>" && npm ci',
    '# comment <script>\nCOPY . .',
    'ENV PORT=8000\nEXPOSE 8000',
    'CMD ["node", "</code></pre><script>alert(1)</script>"]',
    'HEALTHCHECK CMD curl -f http://localhost/ || exit 1',
];
check('dockerfile strip-spans equals escHtml', () => {
    for (const inp of DOCKER_INPUTS) {
        const got = stripSpans(highlight(inp, 'dockerfile'));
        assert(got === esc(inp), `dockerfile invariant broke on ${JSON.stringify(inp)}\n  got:  ${got}`);
    }
});
check('dockerfile instructions/strings/comments spanned', () => {
    const out = highlight('FROM x\n# c\nRUN echo "hi"', 'dockerfile');
    assert(out.includes('<span class="tok-keyword">FROM</span>'), 'FROM not keyword');
    assert(out.includes('<span class="tok-keyword">RUN</span>'), 'RUN not keyword');
    assert(out.includes('<span class="tok-comment"># c</span>'), 'comment not spanned');
    assert(out.includes('<span class="tok-string">&quot;hi&quot;</span>'), 'string not spanned');
});

// --- helm (go-templated yaml) tokenizer ---
const HELM_INPUTS = [
    'name: {{ include "mychart.fullname" . }}',
    'replicas: {{ .Values.replicaCount | default 1 }}',
    '{{- if .Values.ingress.enabled }}\nkind: Ingress\n{{- end }}',
    'image: "{{ .Values.repo }}:{{ .Values.tag }}"  # <script>',
    'labels: {{- include "x" . | nindent 4 }}',
    '{{/* a template comment with <script> */}}\nkey: value',
    'data: {{ .Files.Get "config.yaml" | quote }}',
    '{{}}\n{{-}}\n{{- end -}}', // degenerate delimiters
    'broken: {{ unterminated action <script>',
];
check('helm strip-spans equals escHtml', () => {
    for (const inp of HELM_INPUTS) {
        const got = stripSpans(highlight(inp, 'helm'));
        assert(got === esc(inp), `helm invariant broke on ${JSON.stringify(inp)}\n  got:  ${got}`);
    }
});
check('helm tokenizes actions + keeps yaml', () => {
    const out = highlight('replicas: {{ .Values.count | default 3 }}', 'helm');
    assert(out.includes('<span class="tok-keyword">replicas</span>'), 'yaml key not spanned');
    assert(out.includes('<span class="tok-keyword">{{</span>'), 'open delimiter not spanned');
    assert(out.includes('<span class="tok-keyword">Values</span>'), 'Values builtin not keyword');
    assert(out.includes('<span class="tok-keyword">default</span>'), 'default func not keyword');
    assert(out.includes('<span class="tok-number">3</span>'), 'number not spanned');
    const x = highlight('{{ "</code></pre><script>alert(1)</script>" }}', 'helm');
    assert(!x.includes('<script') && x.includes('&lt;script&gt;'), 'xss inside an action not escaped');
});
check('helm: }} inside a template string does not close the action early', () => {
    const src = '{{ printf "%s}}" .x }}\nkey: val';
    const out = highlight(src, 'helm');
    assert(stripSpans(out) === esc(src), 'invariant broke on }}-in-string');
    assert((out.match(/<span class="tok-keyword">\{\{<\/span>/g) || []).length === 1, 'action mis-split: more than one {{ opener');
    assert(out.includes('<span class="tok-keyword">key</span>'), 'yaml after the action lost its key');
});

// the custom YAML/Dockerfile scanners don't ride the proven scan(); fuzz the invariant
// (strip-spans === escHtml AND no raw angle survives) across thousands of hostile inputs.
// seeded xorshift32 so it's deterministic/reproducible in CI, never Math.random.
check('fuzz: strip-spans invariant holds on random hostile inputs (every lang)', () => {
    let s = 0x9e3779b9 | 0;
    const rnd = () => { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; s |= 0; return (s >>> 0) / 4294967296; };
    const pick = <T>(a: readonly T[]) => a[Math.floor(rnd() * a.length)];
    const frags = ['<', '>', '&', '"', "'", '#', ':', '-', ' ', '\t', '\n', '/*', '*/', '//', '${', '`',
        '</script>', '</span>', 'FROM ', 'RUN ', 'resource ', 'key:', '- ', '&a', '*a', 'true', '42',
        '"x"', "'y'", '\\', '|', '>-', '[', ']', '{', '}', '0xFF', '<<EOF', 'aws_', '@v4', 'on:',
        '{{', '}}', '{{-', '-}}', '{{/*', '*/}}', '.Values', 'include ', '| nindent 4', '{{ end }}'] as const;
    const langs = ['terraform', 'yaml', 'dockerfile', 'helm', 'gotmpl', 'ts', 'json', 'csharp', 'python'] as const;
    let maxMs = 0;
    for (let n = 0; n < 5000; n++) {
        const len = 1 + Math.floor(rnd() * 30);
        let inp = '';
        for (let k = 0; k < len; k++) inp += pick(frags);
        const lang = pick(langs);
        const t0 = process.hrtime.bigint();
        const out = highlight(inp, lang);
        maxMs = Math.max(maxMs, Number(process.hrtime.bigint() - t0) / 1e6);
        assert(stripSpans(out) === esc(inp), `fuzz invariant broke (${lang}) on ${JSON.stringify(inp)}\n  got: ${stripSpans(out)}`);
        const bare = out.replace(/<span class="tok-[a-z]+">/g, '').replace(/<\/span>/g, '');
        assert(!/[<>]/.test(bare), `fuzz leaked a raw angle bracket (${lang}) on ${JSON.stringify(inp)}: ${bare}`);
    }
    assert(maxMs < 100, `fuzz single render too slow: ${maxMs.toFixed(1)}ms`);
    console.log(`    (5000 fuzz inputs across ${langs.length} langs, slowest ${maxMs.toFixed(1)}ms)`);
});

check('linear time on a pathological block (no ReDoS)', () => {
    const evilTs = '/*'.repeat(40000) + "'".repeat(40000) + '`'.repeat(40000);
    const evilJson = '"'.repeat(40000) + '/*'.repeat(40000) + '-'.repeat(40000);
    const evilCs = '"'.repeat(30000) + '/*'.repeat(30000) + '@"'.repeat(15000);
    const evilPy = '"""'.repeat(15000) + '#'.repeat(30000) + "'".repeat(30000);
    const evilHcl = '/*'.repeat(40000) + '"'.repeat(40000) + '#'.repeat(40000);
    const evilYaml = 'a'.repeat(40000) + '\n' + '"'.repeat(40000) + '\n' + ':'.repeat(40000) + '\nv: ' + '1.'.repeat(40000) + '=';
    const evilDocker = '#'.repeat(40000) + '\n' + '"'.repeat(40000) + '\n' + 'FROM '.repeat(8000);
    const evilHelm = '{{'.repeat(40000) + '\n' + '{{ "}}" '.repeat(15000) + '\n' + '{{ '.repeat(10000) + '}}'.repeat(10000);
    let maxMs = 0;
    for (const [lang, evil] of [['ts', evilTs], ['json', evilJson], ['csharp', evilCs], ['python', evilPy], ['terraform', evilHcl], ['yaml', evilYaml], ['dockerfile', evilDocker], ['helm', evilHelm]] as const) {
        const t0 = process.hrtime.bigint();
        const out = highlight(evil, lang);
        maxMs = Math.max(maxMs, Number(process.hrtime.bigint() - t0) / 1e6);
        assert(stripSpans(out) === esc(evil), `invariant broke on pathological ${lang} input`);
    }
    assert(maxMs < 500, `too slow: ${maxMs.toFixed(0)}ms on 120k pathological chars`);
    console.log(`    (${maxMs.toFixed(0)}ms max for 120k pathological chars)`);
});

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
