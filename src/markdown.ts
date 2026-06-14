/*
 * Markdown, the boring-on-purpose way. Escape every run, never let raw HTML through,
 * only emit tags I wrote myself. That collapses the whole XSS problem down to one
 * question — is this URL safe? — and safeUrl answers it. No marked, no DOMPurify, no
 * parser dep, so nothing here is going to wake me up at 3am with a CVE.
 *
 * Handles headings, paragraphs, bold/italic, inline + fenced code, links, images,
 * ul/ol, blockquotes, hr. That's a blog. You don't need the rest of CommonMark.
 */

import { highlight } from './highlight.ts';

const MAX_INPUT = 256 * 1024;
const MAX_DEPTH = 12;

const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };
const escHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ESC[c]);
const escAttr = (s: string) => s.replace(/[&<>"'`]/g, (c) => ESC[c]);

/* the entity tricks people reach for to sneak a scheme past the allowlist —
 * javascript&#58;, &#x6a;.., &colon;. decode them so we judge what the browser would
 * actually see, not what got typed. amp first, so &amp;#58; unfolds all the way down */
function decodeEntities(s: string) {
    return s
        .replace(/&amp;/gi, '&')
        .replace(/&#x([0-9a-f]+);?/gi, (_, h) => { try { return String.fromCodePoint(parseInt(h, 16)); } catch { return ''; } })
        .replace(/&#(\d+);?/g, (_, d) => { try { return String.fromCodePoint(parseInt(d, 10)); } catch { return ''; } })
        .replace(/&colon;/gi, ':')
        .replace(/&sol;/gi, '/')
        .replace(/&(?:Tab|NewLine);/gi, ' ');
}

/*
 * Allowlist, not blocklist. Only a Sith deals in absolutes — on a URL
 * boundary, be the Sith: three schemes, no exceptions, everything else dies. Relative
 * and anchor URLs pass (no scheme to abuse). Anything with a scheme gets decoded,
 * stripped of the whitespace/control junk used to split "java\tscript:", lowercased,
 * then checked against http/https/mailto. Miss the list and you come back null — the
 * link renders as inert escaped text and goes precisely nowhere.
 */
export function safeUrl(raw: string): string | null {
    const url = raw.trim();
    if (url === '') return null;
    // judge on the form the BROWSER would act on: decode entities (so javascript&#58;
    // can't hide its colon) and strip control/space (so java\tscript: can't split it).
    // we emit the original url, but the verdict is on the decoded probe.
    const probe = decodeEntities(url).replace(/[\u0000-\u0020]/g, '').toLowerCase();
    if (/^[\\/]{2,}/.test(probe)) return null; // //host or \\host — browsers resolve these to a foreign origin
    if (/^(?:[/#?]|\.{1,2}\/)/.test(probe)) return url; // relative or anchor
    const colon = probe.indexOf(':');
    const pathStart = probe.search(/[/?#]/);
    if (colon === -1 || (pathStart !== -1 && pathStart < colon)) return url; // no scheme before the path
    const scheme = probe.slice(0, colon);
    return scheme === 'http' || scheme === 'https' || scheme === 'mailto' ? url : null;
}

function linkOrImage(src: string, isImg: boolean, depth: number) {
    // [text](url) / ![alt](url), optional "title". url stops at whitespace or ).
    // the quantifiers are BOUNDED on purpose. leave [^\]]* unbounded and N open brackets
    // with no close each kick off an O(N) scan to the end — O(N^2), and a 256KB '[' bomb
    // hangs the render for ~42 seconds. ask me how I know. bounding each part keeps it linear.
    const re = /^!?\[([^\]]{0,512})\]\(\s*([^)\s]{1,2048})(?:\s+"([^"]{0,512})")?\s*\)/;
    const m = re.exec(src);
    if (!m) return null;
    const url = safeUrl(m[2]);
    const title = m[3] ? ` title="${escAttr(m[3])}"` : '';
    if (!url) return { html: escHtml(m[0]), len: m[0].length }; // bad scheme -> literal
    if (isImg) {
        // gifs get a marker class so the client island can freeze frame 0 and make you click
        // to play. the class is a fixed string, url/alt still escaped — XSS model doesn't budge
        const gif = /\.gif(?:[?#]|$)/i.test(url) ? ' class="gif-player"' : '';
        return { html: `<img src="${escAttr(url)}" alt="${escAttr(m[1])}"${title} loading="lazy"${gif}>`, len: m[0].length };
    }
    return { html: `<a href="${escAttr(url)}"${title} rel="noopener noreferrer">${inline(m[1], depth + 1)}</a>`, len: m[0].length };
}

/* walk the string char by char, escape the literal runs, wrap the markdown bits in
 * tags I emit myself. regexes are anchored so they only fire on a trigger char, and
 * there are no nested quantifiers — nothing here backtracks into next week */
function inline(src: string, depth = 0): string {
    if (depth > MAX_DEPTH) return escHtml(src);
    let out = '';
    let i = 0;
    while (i < src.length) {
        const c = src[i];
        const rest = src.slice(i);

        if (c === '`') {
            const m = /^(`+)([\s\S]*?)\1(?!`)/.exec(rest);
            if (m) { out += `<code>${escHtml(m[2].trim())}</code>`; i += m[0].length; continue; }
        }
        if (c === '!' && src[i + 1] === '[') {
            const r = linkOrImage(rest, true, depth);
            if (r) { out += r.html; i += r.len; continue; }
        }
        if (c === '[') {
            const r = linkOrImage(rest, false, depth);
            if (r) { out += r.html; i += r.len; continue; }
        }
        if ((c === '*' || c === '_') && src[i + 1] === c) {
            const m = new RegExp(`^\\${c}\\${c}([\\s\\S]+?)\\${c}\\${c}`).exec(rest);
            if (m) { out += `<strong>${inline(m[1], depth + 1)}</strong>`; i += m[0].length; continue; }
        }
        if (c === '*' || c === '_') {
            const m = new RegExp(`^\\${c}([\\s\\S]+?)\\${c}`).exec(rest);
            if (m) { out += `<em>${inline(m[1], depth + 1)}</em>`; i += m[0].length; continue; }
        }
        out += escHtml(c);
        i++;
    }
    return out;
}

const BLOCK_START = /^(#{1,6}\s|>|```|~~~|[-*+]\s|\d+\.\s)/;
const HR = /^([-*_])\1{2,}\s*$/;
const LIST_ITEM = /^(\s*)([-*+]|\d+\.)\s+(.*)$/;
// one measure of indent width, tabs expanded. the parent's reference and every per-line
// compare have to run through this same function — mix raw length with expanded length and
// a tab-indented child looks deeper than itself, parseList makes no progress, spins forever.
const indentWidth = (s: string) => s.replace(/\t/g, '  ').length;

/* indent-driven nested lists. item text still runs through inline() — same
 * escape-everything path as a flat list — and a deeper-indented run below an item turns
 * into a child <ul>/<ol> nested inside it. only my own structural tags come out, so the
 * XSS surface doesn't move. depth is capped at MAX_DEPTH so staircase indentation can't
 * recurse the stack into a big ball of wibbly-wobbly timey-wimey stuff; past the cap it
 * just falls back to a paragraph. */
function parseList(lines: string[], start: number, depth: number): { html: string; next: number } {
    const first = LIST_ITEM.exec(lines[start]);
    if (!first) return { html: '', next: start + 1 }; // dispatch already matched LIST_ITEM; bail soft instead of asserting
    const indent = indentWidth(first[1]);
    const ordered = /\d/.test(first[2]);
    const items: string[] = [];
    let i = start;

    while (i < lines.length) {
        const m = LIST_ITEM.exec(lines[i]);
        if (!m) break;
        const ind = indentWidth(m[1]);
        if (ind < indent) break;                                  // dedent — hand back to the parent list
        if (ind === indent && /\d/.test(m[2]) !== ordered) break; // marker flipped ul<->ol — that's a new sibling list

        if (ind > indent) {
            // a deeper run the per-item lookahead below didn't already swallow — hang it off the last item
            if (items.length && depth < MAX_DEPTH) {
                const sub = parseList(lines, i, depth + 1);
                if (sub.next <= i) break; // recursion has to eat at least one line or we loop forever
                items[items.length - 1] += sub.html;
                i = sub.next;
                continue;
            }
            break;
        }

        let content = inline(m[3].trim());
        i++;
        const nm = i < lines.length ? LIST_ITEM.exec(lines[i]) : null;
        if (nm && indentWidth(nm[1]) > indent && depth < MAX_DEPTH) {
            const sub = parseList(lines, i, depth + 1);
            if (sub.next > i) { content += sub.html; i = sub.next; } // only fold it in if it actually advanced
        }
        items.push(content);
    }

    const tag = ordered ? 'ol' : 'ul';
    return { html: `<${tag}>${items.map((it) => `<li>${it}</li>`).join('')}</${tag}>`, next: i };
}

export function renderMarkdown(input: string, depth = 0): string {
    let src = input.length > MAX_INPUT ? input.slice(0, MAX_INPUT) : input;
    src = src.replace(/\r\n?/g, '\n');
    const lines = src.split('\n');
    const blocks: string[] = [];
    let i = 0;

    while (i < lines.length) {
        const line = lines[i];
        if (line.trim() === '') { i++; continue; }

        const fence = /^(```|~~~)(.*)$/.exec(line);
        if (fence) {
            const close = fence[1];
            const lang = fence[2].trim().split(/\s+/)[0];
            const buf: string[] = [];
            i++;
            while (i < lines.length && !lines[i].startsWith(close)) { buf.push(lines[i]); i++; }
            i++; // closing fence
            const cls = /^[a-zA-Z0-9-]+$/.test(lang) ? ` class="language-${lang}"` : '';
            // strip trailing whitespace per line, leave the author's blank lines and indentation alone
            const code = buf.map((l) => l.replace(/\s+$/, '')).join('\n');
            blocks.push(`<pre><code${cls}>${highlight(code, lang)}\n</code></pre>`);
            continue;
        }

        const h = /^(#{1,6})\s+(.*)$/.exec(line);
        if (h) { const lv = h[1].length; blocks.push(`<h${lv}>${inline(h[2].trim())}</h${lv}>`); i++; continue; }

        if (HR.test(line)) { blocks.push('<hr>'); i++; continue; }

        if (/^>\s?/.test(line)) {
            const buf: string[] = [];
            while (i < lines.length && /^>\s?/.test(lines[i])) { buf.push(lines[i].replace(/^>\s?/, '')); i++; }
            // cap the recursion: a long run of leading '>' peels one off per level, and ~7KB of
            // '>' blows the stack with a RangeError — well under MAX_INPUT, so the cap matters.
            // past it, stop recursing and dump the rest of the body as one escaped paragraph.
            const body = buf.join('\n');
            const inner = depth < MAX_DEPTH ? renderMarkdown(body, depth + 1) : `<p>${inline(body.trim())}</p>`;
            blocks.push(`<blockquote>${inner}</blockquote>`);
            continue;
        }

        // a list starts at a column-0 marker; parseList walks the indentation out from there.
        // dispatch on LIST_ITEM itself (m[1] empty means column 0) so parseList's first exec is
        // guaranteed to match. a looser prefix test could match where LIST_ITEM won't — a U+2028
        // in the line, say — and then parseList gets handed a line it can't parse.
        const lm = LIST_ITEM.exec(line);
        if (lm && lm[1] === '') {
            const { html, next } = parseList(lines, i, 0);
            blocks.push(html);
            i = next;
            continue;
        }

        // paragraph fallback. grab the current line first, unconditionally: it got here because
        // no block handler above claimed it (a "- " or "# " line whose handler bailed on a
        // U+2028, say), and BLOCK_START would otherwise pin the while loop at zero progress.
        const buf: string[] = [lines[i]];
        i++;
        while (i < lines.length && lines[i].trim() !== '' && !BLOCK_START.test(lines[i]) && !HR.test(lines[i])) { buf.push(lines[i]); i++; }
        blocks.push(`<p>${inline(buf.join('\n').trim())}</p>`);
    }

    return blocks.join('\n');
}
