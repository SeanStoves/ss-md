'use client';

import { useEffect, useRef, useState } from 'react';

/*
 * Renders the post html and decorates it on the client: a copy button on each code
 * block, click-to-zoom on each image. The html is the markdown compiler's
 * already-escaped output, so all this does is attach behaviour — the image src and
 * code text it reads were safe the moment they got rendered.
 */

const COPY_SVG =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
const CHECK_SVG =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>';
const PLAY_SVG = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M8 5v14l11-7z"/></svg>';

export function PostBody({ html }: { html: string }) {
    const ref = useRef<HTMLDivElement>(null);
    const [zoom, setZoom] = useState<{ src: string; alt: string } | null>(null);

    useEffect(() => {
        const root = ref.current;
        if (!root) return;
        const cleanups: (() => void)[] = [];

        // copy button per code block. wrap the <pre> so the button can sit pinned at the
        // visible top-right instead of scrolling away with long lines. cleanup fully undoes
        // the wrap so re-running the effect is idempotent — strict-mode double-invoke in dev
        // included — and we never leave orphaned buttons with no handler behind.
        root.querySelectorAll('pre').forEach((pre) => {
            const parent = pre.parentNode;
            if (!parent) return;
            const wrap = document.createElement('div');
            wrap.className = 'code-block';
            parent.insertBefore(wrap, pre);
            wrap.appendChild(pre);

            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'code-copy';
            btn.setAttribute('aria-label', 'Copy code');
            btn.innerHTML = COPY_SVG;
            let revert: ReturnType<typeof setTimeout> | undefined;
            const onClick = async () => {
                const text = (pre.querySelector('code') ?? pre).textContent ?? '';
                try {
                    await navigator.clipboard.writeText(text);
                    btn.innerHTML = CHECK_SVG;
                    btn.classList.add('copied');
                    clearTimeout(revert);
                    revert = setTimeout(() => { btn.innerHTML = COPY_SVG; btn.classList.remove('copied'); }, 1500);
                } catch {
                    /* no clipboard — insecure context or the user said no. nothing to do */
                }
            };
            btn.addEventListener('click', onClick);
            wrap.appendChild(btn);
            cleanups.push(() => {
                clearTimeout(revert);
                btn.removeEventListener('click', onClick);
                parent.insertBefore(pre, wrap); // unwrap: pre back where it was, then drop the wrapper and its button
                wrap.remove();
            });
        });

        // gif click-to-play: paint frame 0 onto a canvas, swap in the animated gif on click.
        // native canvas, no gif-decoder dep. cleanup reverses the wrap (strict-mode safe).
        root.querySelectorAll<HTMLImageElement>('img.gif-player').forEach((img) => {
            const parent = img.parentNode;
            if (!parent) return;
            const wrap = document.createElement('span');
            wrap.className = 'gif-wrap';
            parent.insertBefore(wrap, img);
            wrap.appendChild(img);
            img.style.display = 'none'; // hide it before it can animate; the canvas shows frame 0 instead

            const canvas = document.createElement('canvas');
            wrap.insertBefore(canvas, img);

            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'gif-play';
            btn.setAttribute('aria-label', img.alt ? `Play GIF: ${img.alt}` : 'Play GIF');
            btn.innerHTML = PLAY_SVG;
            wrap.appendChild(btn);

            // a fresh decode sits on frame 0; drawImage in onload grabs it before the loop moves on
            const probe = new Image();
            probe.onload = () => {
                canvas.width = probe.naturalWidth || 1;
                canvas.height = probe.naturalHeight || 1;
                canvas.getContext('2d')?.drawImage(probe, 0, 0);
            };
            probe.onerror = () => { img.style.display = ''; canvas.remove(); btn.remove(); }; // decode failed, just show the img
            probe.src = img.src;

            let played = false;
            const play = () => {
                if (played) return;
                played = true;
                canvas.style.display = 'none';
                btn.style.display = 'none';
                img.style.display = ''; // it sat display:none the whole time, so it starts from frame 0
            };
            wrap.addEventListener('click', play);

            cleanups.push(() => {
                wrap.removeEventListener('click', play);
                probe.onload = null;
                probe.onerror = null;
                img.style.display = '';
                parent.insertBefore(img, wrap); // unwrap, put the img back
                wrap.remove();
            });
        });

        // click any image to blow it up full-screen
        const onClick = (e: MouseEvent) => {
            const t = e.target as HTMLElement;
            if (t.tagName === 'IMG') {
                const img = t as HTMLImageElement;
                setZoom({ src: img.currentSrc || img.src, alt: img.alt });
            }
        };
        root.addEventListener('click', onClick);
        cleanups.push(() => root.removeEventListener('click', onClick));

        return () => cleanups.forEach((fn) => fn());
    }, [html]);

    useEffect(() => {
        if (!zoom) return;
        const prevOverflow = document.body.style.overflow;
        document.body.style.overflow = 'hidden'; // freeze the background scroll while the overlay is up
        const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setZoom(null); };
        document.addEventListener('keydown', onKey);
        return () => {
            document.body.style.overflow = prevOverflow;
            document.removeEventListener('keydown', onKey);
        };
    }, [zoom]);

    return (
        <>
            <div ref={ref} className="post-content" dangerouslySetInnerHTML={{ __html: html }} />
            {zoom && (
                <div
                    role="dialog"
                    aria-modal="true"
                    className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-4 sm:p-8"
                    onClick={() => setZoom(null)}
                >
                    {/* plain img on purpose: src is external / mounted at runtime, nothing for next/image to optimize */}
                    <img src={zoom.src} alt={zoom.alt} className="max-h-full max-w-full rounded shadow-2xl" onClick={(e) => e.stopPropagation()} />
                    <button onClick={() => setZoom(null)} aria-label="Close" className="absolute right-3 top-3 text-3xl leading-none text-white/70 hover:text-white sm:right-5 sm:top-5">
                        ✕
                    </button>
                </div>
            )}
        </>
    );
}
