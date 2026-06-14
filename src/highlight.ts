/*
 * Tiny syntax highlighter for fenced code blocks. No Prism, no highlight.js — same
 * reason as the markdown compiler next door: a hand-rolled tokenizer is less code and
 * zero CVE surface. Tokenizes a handful of languages I actually write about and wraps
 * each token in a <span class="tok-..">. Anything it doesn't know falls back to plain
 * escaped text.
 *
 * XSS: the only html out of here is the fixed span open/close tags with a class from a
 * closed set. Every char of the code goes through escHtml, so a block with
 * </span><script> in it renders inert — same as the compiler's plain escape path. The
 * invariant — strip the spans and you get escHtml(code) back — is pinned in
 * tests/highlight.ts. This escHtml is a copy of markdown.ts's; keep the two in sync.
 */

const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const escHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ESC[c]);

const span = (cls: string, text: string) => `<span class="tok-${cls}">${escHtml(text)}</span>`;

const TS_KEYWORDS = new Set([
    'abstract', 'as', 'async', 'await', 'break', 'case', 'catch', 'class', 'const', 'continue',
    'debugger', 'declare', 'default', 'delete', 'do', 'else', 'enum', 'export', 'extends', 'false',
    'finally', 'for', 'from', 'function', 'get', 'if', 'implements', 'import', 'in', 'instanceof',
    'interface', 'is', 'keyof', 'let', 'new', 'null', 'of', 'private', 'protected', 'public',
    'readonly', 'return', 'satisfies', 'set', 'static', 'super', 'switch', 'this', 'throw', 'true',
    'try', 'type', 'typeof', 'undefined', 'var', 'void', 'while', 'yield',
]);

/* sticky (y) so each rule matches AT the cursor without re-slicing the string —
 * that's what keeps the scan linear. order matters: comments and strings before
 * words. every pattern eats at least one char so the loop can't stall, and none
 * backtrack catastrophically since the string alternations are disjoint. */
const TS_RULES: [RegExp, string][] = [
    [/\/\/[^\n]*/y, 'comment'],
    [/\/\*[\s\S]*?\*\//y, 'comment'],
    [/'(?:\\.|[^'\\\n])*'/y, 'string'],
    [/"(?:\\.|[^"\\\n])*"/y, 'string'],
    [/`(?:\\.|[^`\\])*`/y, 'string'],
    [/0[xX][0-9a-fA-F]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?/y, 'number'],
    [/[A-Za-z_$][\w$]*/y, 'ident'],
];

/* one scanner for every C-family language: first matching rule wins, an ident turns
 * into a keyword span if it's in the set, anything unmatched gets escaped as-is.
 * output is span wrappers around escaped text and nothing else, so the strip-spans
 * invariant holds for whatever language flows through here. */
function scan(code: string, rules: [RegExp, string][], keywords: Set<string>): string {
    let out = '';
    let i = 0;
    const n = code.length;
    next: while (i < n) {
        for (const [re, type] of rules) {
            re.lastIndex = i;
            const m = re.exec(code);
            if (m) {
                const text = m[0];
                out += type === 'ident' ? (keywords.has(text) ? span('keyword', text) : escHtml(text)) : span(type, text);
                i += text.length || 1;
                continue next;
            }
        }
        out += escHtml(code[i]);
        i++;
    }
    return out;
}

const CS_KEYWORDS = new Set([
    'abstract', 'as', 'async', 'await', 'base', 'bool', 'break', 'byte', 'case', 'catch', 'char',
    'checked', 'class', 'const', 'continue', 'decimal', 'default', 'delegate', 'do', 'double',
    'dynamic', 'else', 'enum', 'event', 'explicit', 'extern', 'false', 'finally', 'fixed', 'float',
    'for', 'foreach', 'get', 'goto', 'if', 'implicit', 'in', 'init', 'int', 'interface', 'internal',
    'is', 'lock', 'long', 'nameof', 'namespace', 'new', 'null', 'object', 'operator', 'out',
    'override', 'params', 'partial', 'private', 'protected', 'public', 'readonly', 'record', 'ref',
    'return', 'sbyte', 'sealed', 'set', 'short', 'sizeof', 'stackalloc', 'static', 'string', 'struct',
    'switch', 'this', 'throw', 'true', 'try', 'typeof', 'uint', 'ulong', 'unchecked', 'unsafe',
    'ushort', 'using', 'value', 'var', 'virtual', 'void', 'volatile', 'when', 'where', 'while', 'yield',
]);
const CS_RULES: [RegExp, string][] = [
    [/\/\/[^\n]*/y, 'comment'],
    [/\/\*[\s\S]*?\*\//y, 'comment'],
    [/(?:@\$?|\$@)"(?:""|[^"])*"/y, 'string'], // verbatim / interpolated-verbatim
    [/\$?"(?:\\.|[^"\\\n])*"/y, 'string'], // regular / interpolated
    [/'(?:\\.|[^'\\\n])'/y, 'string'], // single char
    [/0[xX][0-9a-fA-F_]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?[fFdDmMlLuU]*/y, 'number'],
    [/[A-Za-z_]\w*/y, 'ident'],
];

const PY_KEYWORDS = new Set([
    'False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await', 'break', 'case', 'class',
    'continue', 'def', 'del', 'elif', 'else', 'except', 'finally', 'for', 'from', 'global', 'if',
    'import', 'in', 'is', 'lambda', 'match', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return',
    'self', 'try', 'while', 'with', 'yield',
]);
const PY_RULES: [RegExp, string][] = [
    [/#[^\n]*/y, 'comment'],
    [/[rbfuRBFU]{0,3}"""[\s\S]*?"""/y, 'string'],
    [/[rbfuRBFU]{0,3}'''[\s\S]*?'''/y, 'string'],
    [/[rbfuRBFU]{0,3}"(?:\\.|[^"\\\n])*"/y, 'string'],
    [/[rbfuRBFU]{0,3}'(?:\\.|[^'\\\n])*'/y, 'string'],
    [/0[xXoObB][0-9a-fA-F_]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?j?/y, 'number'],
    [/[A-Za-z_]\w*/y, 'ident'],
];

const highlightTs = (code: string) => scan(code, TS_RULES, TS_KEYWORDS);
const highlightCs = (code: string) => scan(code, CS_RULES, CS_KEYWORDS);
const highlightPy = (code: string) => scan(code, PY_RULES, PY_KEYWORDS);

/* json (and jsonc): a string is a key if a colon follows it, otherwise it's a value.
 * comments are tolerated for jsonc/config files. same span-only output as highlightTs,
 * so the strip-spans invariant (tests/highlight.ts) holds here too. */
const JSON_STR = /"(?:\\.|[^"\\\n])*"/y;
const JSON_NUM = /-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
const JSON_LIT = /(?:true|false|null)\b/y;
const JSON_LINE = /\/\/[^\n]*/y;
const JSON_BLOCK = /\/\*[\s\S]*?\*\//y;
const JSON_COLON = /\s*:/y;

function highlightJson(code: string): string {
    let out = '';
    let i = 0;
    const n = code.length;
    while (i < n) {
        let m: RegExpExecArray | null;
        JSON_STR.lastIndex = i;
        if ((m = JSON_STR.exec(code))) {
            JSON_COLON.lastIndex = i + m[0].length;
            out += span(JSON_COLON.test(code) ? 'keyword' : 'string', m[0]);
            i += m[0].length;
            continue;
        }
        JSON_LINE.lastIndex = i;
        if ((m = JSON_LINE.exec(code))) { out += span('comment', m[0]); i += m[0].length; continue; }
        JSON_BLOCK.lastIndex = i;
        if ((m = JSON_BLOCK.exec(code))) { out += span('comment', m[0]); i += m[0].length; continue; }
        JSON_NUM.lastIndex = i;
        if ((m = JSON_NUM.exec(code))) { out += span('number', m[0]); i += m[0].length; continue; }
        JSON_LIT.lastIndex = i;
        if ((m = JSON_LIT.exec(code))) { out += span('keyword', m[0]); i += m[0].length; continue; }
        out += escHtml(code[i]);
        i++;
    }
    return out;
}

/* Terraform / HCL. C-family enough to ride the shared scan(): # and // line
 * comments, slash-star block comments, "..." strings, numbers, and the block-type /
 * scope words below as keywords. heredocs aren't special-cased — the body just
 * tokenizes as plain HCL, which is harmless and keeps the scan linear. */
const HCL_KEYWORDS = new Set([
    'resource', 'variable', 'module', 'output', 'data', 'provider', 'locals', 'terraform',
    'true', 'false', 'null', 'for', 'in', 'if', 'else', 'endfor', 'endif', 'dynamic',
    'depends_on', 'count', 'for_each', 'lifecycle', 'var', 'local', 'path', 'each', 'self',
]);
const HCL_RULES: [RegExp, string][] = [
    [/#[^\n]*/y, 'comment'],
    [/\/\/[^\n]*/y, 'comment'],
    [/\/\*[\s\S]*?\*\//y, 'comment'],
    [/"(?:\\.|[^"\\\n])*"/y, 'string'],
    [/0[xX][0-9a-fA-F]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?/y, 'number'],
    [/[A-Za-z_][\w-]*/y, 'ident'],
];
const highlightHcl = (code: string) => scan(code, HCL_RULES, HCL_KEYWORDS);

/* YAML (GitHub Actions). Not C-family — it's line-shaped, so it gets its own
 * position scanner: a mapping key (word before ": ") becomes a keyword, plus #
 * comments, quoted scalars, &anchors/*aliases, and bool/null/number scalars. every
 * byte comes out via span()/escHtml and the loop always advances, so the strip-spans
 * invariant holds and it can't stall. */
const YAML_COMMENT = /#[^\n]*/y;
const YAML_DQ = /"(?:\\.|[^"\\\n])*"/y;
const YAML_SQ = /'(?:''|[^'\n])*'/y;
const YAML_KEY = /[^\s#&*!|>'"-][^:#\n]*?(?=:(?:\s|$))/y;
const YAML_ANCHOR = /[&*][\w-]+/y;
const YAML_LIT = /(?:true|false|null|yes|no|on|off|True|False|Null|TRUE|FALSE|NULL|~)(?=$|[\s,\]}])/y;
// dotted groups capped at 8 so versions/semver (1.2.3) and IPs colour as numbers,
// while the backtrack on a non-terminator stays O(8) per position — never goes quadratic
const YAML_NUM = /-?\d[\d_]*(?:\.\d+){0,8}(?:[eE][+-]?\d+)?(?=$|[\s,\]}])/y;

function highlightYaml(code: string): string {
    let out = '', i = 0;
    const n = code.length;
    let contentStart = true; // at the first non-indent char of a line — where a mapping key can start
    while (i < n) {
        const c = code[i];
        if (c === '\n') { out += '\n'; i++; contentStart = true; continue; }
        if (c === ' ' || c === '\t') { out += c; i++; continue; } // indent / spacing, still at content start
        // a "- " list marker keeps content-start set so "- key: v" still flags the key
        if (contentStart && c === '-' && (code[i + 1] === ' ' || code[i + 1] === '\n' || i + 1 === n)) {
            out += '-'; i++; continue;
        }
        if (c === '#' && (i === 0 || code[i - 1] === ' ' || code[i - 1] === '\t' || code[i - 1] === '\n')) {
            YAML_COMMENT.lastIndex = i; const m = YAML_COMMENT.exec(code);
            if (m) { out += span('comment', m[0]); i += m[0].length; contentStart = false; continue; }
        }
        if (contentStart) {
            contentStart = false;
            YAML_KEY.lastIndex = i; const km = YAML_KEY.exec(code);
            if (km) { out += span('keyword', km[0]); i += km[0].length; continue; }
        }
        if (c === '"') { YAML_DQ.lastIndex = i; const m = YAML_DQ.exec(code); if (m) { out += span('string', m[0]); i += m[0].length; continue; } }
        if (c === "'") { YAML_SQ.lastIndex = i; const m = YAML_SQ.exec(code); if (m) { out += span('string', m[0]); i += m[0].length; continue; } }
        if (c === '&' || c === '*') { YAML_ANCHOR.lastIndex = i; const m = YAML_ANCHOR.exec(code); if (m) { out += span('keyword', m[0]); i += m[0].length; continue; } }
        YAML_LIT.lastIndex = i; { const m = YAML_LIT.exec(code); if (m) { out += span('keyword', m[0]); i += m[0].length; continue; } }
        YAML_NUM.lastIndex = i; { const m = YAML_NUM.exec(code); if (m) { out += span('number', m[0]); i += m[0].length; continue; } }
        out += escHtml(c); i++;
    }
    return out;
}

/* Dockerfile. Line-shaped too: the instruction word at the start of a line is the
 * keyword, plus # comments and "..."/'...' strings. Same span()/escHtml-only,
 * always-advancing scanner shape as YAML. */
const DOCKER_INSTR = /(?:FROM|RUN|CMD|LABEL|MAINTAINER|EXPOSE|ENV|ADD|COPY|ENTRYPOINT|VOLUME|USER|WORKDIR|ARG|ONBUILD|STOPSIGNAL|HEALTHCHECK|SHELL)\b/y;
const DOCKER_COMMENT = /#[^\n]*/y;
const DOCKER_DQ = /"(?:\\.|[^"\\\n])*"/y;
const DOCKER_SQ = /'(?:\\.|[^'\\\n])*'/y;

function highlightDocker(code: string): string {
    let out = '', i = 0;
    const n = code.length;
    let lineStart = true;
    while (i < n) {
        const c = code[i];
        if (c === '\n') { out += '\n'; i++; lineStart = true; continue; }
        if (c === ' ' || c === '\t') { out += c; i++; continue; } // leading indent keeps line-start set
        if (c === '#' && (i === 0 || code[i - 1] === ' ' || code[i - 1] === '\t' || code[i - 1] === '\n')) {
            DOCKER_COMMENT.lastIndex = i; const m = DOCKER_COMMENT.exec(code);
            if (m) { out += span('comment', m[0]); i += m[0].length; lineStart = false; continue; }
        }
        if (lineStart) {
            lineStart = false;
            DOCKER_INSTR.lastIndex = i; const m = DOCKER_INSTR.exec(code);
            if (m) { out += span('keyword', m[0]); i += m[0].length; continue; }
        }
        if (c === '"') { DOCKER_DQ.lastIndex = i; const m = DOCKER_DQ.exec(code); if (m) { out += span('string', m[0]); i += m[0].length; continue; } }
        if (c === "'") { DOCKER_SQ.lastIndex = i; const m = DOCKER_SQ.exec(code); if (m) { out += span('string', m[0]); i += m[0].length; continue; } }
        out += escHtml(c); i++;
    }
    return out;
}

/* Helm charts = Go-templated YAML. A double-brace action (optional - chomp markers,
 * plus Go template comments) gets tokenized with Go-template rules; the YAML between
 * actions rides highlightYaml. Glue together pieces that each preserve the invariant
 * and the whole thing still preserves it — escHtml works per char. The action body
 * length is capped so a run of unterminated open-braces can't drive an O(n^2) scan. */
const HELM_KEYWORDS = new Set([
    'if', 'else', 'end', 'range', 'with', 'define', 'template', 'block', 'include', 'and', 'or', 'not',
    'eq', 'ne', 'lt', 'gt', 'le', 'ge', 'default', 'required', 'empty', 'coalesce', 'ternary', 'quote',
    'squote', 'nindent', 'indent', 'toYaml', 'fromYaml', 'toJson', 'fromJson', 'tpl', 'print', 'printf',
    'b64enc', 'b64dec', 'trim', 'trimSuffix', 'trimPrefix', 'upper', 'lower', 'title', 'replace',
    'contains', 'hasPrefix', 'hasSuffix', 'split', 'list', 'dict', 'get', 'set', 'hasKey', 'merge',
    'len', 'sha256sum', 'now', 'date', 'semverCompare', 'regexMatch',
    'Values', 'Chart', 'Release', 'Files', 'Capabilities', 'Template', 'true', 'false', 'nil',
]);
const GO_RULES: [RegExp, string][] = [
    [/\/\*[\s\S]*?\*\//y, 'comment'],
    [/"(?:\\.|[^"\\\n])*"/y, 'string'],
    [/`[^`]*`/y, 'string'],
    [/-?\d[\d_]*(?:\.\d+)?/y, 'number'],
    [/[A-Za-z_]\w*/y, 'ident'],
];
// string-aware so a literal }} inside a "..."/`...` scalar doesn't close the action early.
// the body alternatives have disjoint first chars (", `, }, everything-else) so there's no
// backtracking ambiguity, and both the per-string char count and the iteration count are
// capped — so a {{ "}}" bomb stays linear. an unterminated string just ends the body, the
// action fails to match, and it falls through to highlightYaml still fully escaped.
const HELM_ACTION = /\{\{-?(?:"(?:\\.|[^"\\]){0,256}"|`[^`]{0,256}`|\}(?!\})|[^}"`]){0,512}?-?\}\}/y;

function helmAction(s: string): string {
    const open = s.startsWith('{{-') ? '{{-' : '{{';
    const close = s.endsWith('-}}') ? '-}}' : '}}';
    if (open.length + close.length > s.length) return span('keyword', s); // degenerate case like {{-}}, no body to slice
    const inner = s.slice(open.length, s.length - close.length);
    return span('keyword', open) + scan(inner, GO_RULES, HELM_KEYWORDS) + span('keyword', close);
}

function highlightHelm(code: string): string {
    let out = '', i = 0, last = 0;
    const n = code.length;
    // cache the next "}}" so a run of unterminated "{{" can't re-scan to it every single time —
    // only recompute once we've passed it. keeps the whole pass O(n), no {{-bomb blowup.
    let nextClose = code.indexOf('}}');
    while (i < n) {
        if (code[i] === '{' && code[i + 1] === '{') {
            if (nextClose !== -1 && nextClose < i) nextClose = code.indexOf('}}', i);
            if (nextClose === -1) break; // no more closers left — the rest is plain yaml
            if (nextClose - i <= 512) {
                HELM_ACTION.lastIndex = i;
                const m = HELM_ACTION.exec(code);
                if (m) {
                    if (i > last) out += highlightYaml(code.slice(last, i)); // the YAML gap before this action
                    out += helmAction(m[0]);
                    i += m[0].length; last = i; continue;
                }
            }
        }
        i++;
    }
    if (last < n) out += highlightYaml(code.slice(last));
    return out;
}

const TS_LANGS = new Set(['ts', 'tsx', 'typescript', 'js', 'jsx', 'javascript', 'mjs', 'cjs']);
const JSON_LANGS = new Set(['json', 'jsonc', 'json5']);
const CS_LANGS = new Set(['cs', 'csharp', 'c#', 'dotnet']);
const PY_LANGS = new Set(['py', 'python', 'py3']);
const HCL_LANGS = new Set(['hcl', 'tf', 'terraform']);
const YAML_LANGS = new Set(['yaml', 'yml']);
const DOCKER_LANGS = new Set(['dockerfile', 'docker']);
const HELM_LANGS = new Set(['helm', 'gotmpl']);

export function highlight(code: string, lang: string): string {
    const l = lang.toLowerCase();
    if (TS_LANGS.has(l)) return highlightTs(code);
    if (JSON_LANGS.has(l)) return highlightJson(code);
    if (CS_LANGS.has(l)) return highlightCs(code);
    if (PY_LANGS.has(l)) return highlightPy(code);
    if (HCL_LANGS.has(l)) return highlightHcl(code);
    if (YAML_LANGS.has(l)) return highlightYaml(code);
    if (DOCKER_LANGS.has(l)) return highlightDocker(code);
    if (HELM_LANGS.has(l)) return highlightHelm(code);
    // these aren't the languages you're looking for, move along —
    // plain escaped text, which is the only safe default anyway
    return escHtml(code);
}
