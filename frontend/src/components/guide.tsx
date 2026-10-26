// A product guide written in Markdown (docs/USER-GUIDE.md), shown with the documentation layout (app.css,
// "Documentation"): contents with an icon per section that follow the reader, a search, and one card per
// "## " section. RadiusOne's Documentation, DNSOne's Help and the PingOmni website all use this file, so
// the guides look the same everywhere; DNSOne copies it with tools/sync-radiusone.sh.
// The Markdown is turned into React elements by the small renderer below, never into raw HTML.
import { useCallback, useEffect, useMemo, useRef, useState, type MouseEvent, type ReactNode } from 'react';
import Icon from '@/components/Icon';

export type GuideSection = { id: string; title: string; body: string[] };

export type GuideProps = {
    /** The guide's Markdown: "# Title", an introduction, "## Contents" (left out), then numbered "## " sections. */
    markdown: string;
    /** The heading above the introduction, e.g. "RadiusOne user guide". */
    title: string;
    /** "This guide describes RadiusOne 2.1.8." when given. */
    product?: string;
    version?: string | null;
    /** Section icons by the section's slug without its number ("dashboard", "zones-authoritative-dns"). */
    icons?: Record<string, string>;
    /** Where relative links (RUNBOOK.md) point, e.g. the repository's docs folder. */
    docsBase?: string;
    /** Renders links to the app's own pages ("/clients"); a plain link when left out. */
    appLink?: (href: string, children: ReactNode, key: string) => ReactNode;
    searchPlaceholder?: string;
    /** The bar the contents and headings stay under. */
    topSelector?: string;
    /** The search box under the introduction (off for a short article). */
    search?: boolean;
};

/** GitHub's heading anchors: "1. What DNSOne does" → "1-what-dnsone-does". */
export function slug(text: string): string {
    return text.toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, '').trim().replace(/\s/g, '-');
}

const plain = (title: string) => title.replace(/^\d+\.\s*/, '');

/** The guide split at its "## " headings: the introduction, then one section each (the contents list is left out). */
export function splitGuide(markdown: string): { intro: string[]; sections: GuideSection[] } {
    const intro: string[] = [];
    const sections: GuideSection[] = [];
    let fence = false;
    for (const line of markdown.split('\n')) {
        if (line.startsWith('```')) fence = !fence;
        if (!fence && line.startsWith('## ')) {
            const title = line.slice(3).trim();
            sections.push({ id: slug(title), title, body: [] });
        } else if (sections.length) {
            sections[sections.length - 1].body.push(line);
        } else if (!line.startsWith('# ') && line.trim() !== '---') {
            intro.push(line);
        }
    }
    return { intro, sections: sections.filter((s) => s.title !== 'Contents') };
}

type Links = Pick<GuideProps, 'docsBase' | 'appLink'>;

/** `code`, **bold**, *italic* and [links](…) inside a line. */
function inline(text: string, links: Links, key = ''): ReactNode[] {
    const out: ReactNode[] = [];
    const pattern = /`([^`]+)`|\*\*(.+?)\*\*|\*([^*\s][^*]*?)\*|\[([^\]]+)\]\(([^)\s]+)\)/g;
    let last = 0;
    let m: RegExpExecArray | null;
    let n = 0;
    while ((m = pattern.exec(text))) {
        if (m.index > last) out.push(text.slice(last, m.index));
        const k = `${key}-${n++}`;
        if (m[1] !== undefined) out.push(<code key={k}>{m[1]}</code>);
        else if (m[2] !== undefined) out.push(<strong key={k}>{inline(m[2], links, k)}</strong>);
        else if (m[3] !== undefined) out.push(<em key={k}>{inline(m[3], links, k)}</em>);
        else {
            const target = m[5];
            const label = inline(m[4], links, k);
            if (target.startsWith('#')) out.push(<a key={k} href={target}>{label}</a>);
            else if (target.startsWith('/')) out.push(links.appLink ? links.appLink(target, label, k) : <a key={k} href={target}>{label}</a>);
            else {
                const url = /^https?:\/\//.test(target) ? target : (links.docsBase ?? '') + target;
                out.push(<a key={k} href={url} target="_blank" rel="noreferrer">{label}</a>);
            }
        }
        last = m.index + m[0].length;
    }
    if (last < text.length) out.push(text.slice(last));
    return out;
}

const cells = (row: string) => row.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
const BLOCK_START = /^(- |\d+\. |\||```|### |> )/;

/** Block-level Markdown: ### headings, paragraphs, - and 1. lists (with continuation lines), tables, code, > notes. */
export function GuideBlocks({ lines, prefix, links }: { lines: string[]; prefix: string; links: Links }): ReactNode {
    const out: ReactNode[] = [];
    let i = 0;
    const key = () => `${prefix}-${out.length}`;
    while (i < lines.length) {
        const line = lines[i];
        const trimmed = line.trim();
        if (!trimmed || trimmed === '---') {
            i++;
        } else if (trimmed.startsWith('```')) {
            const code: string[] = [];
            const indent = line.indexOf('```');
            for (i++; i < lines.length && !lines[i].trim().startsWith('```'); i++) code.push(lines[i].slice(indent));
            i++;
            out.push(<pre key={key()} className="docs-code">{code.join('\n')}</pre>);
        } else if (trimmed.startsWith('### ')) {
            const title = trimmed.slice(4);
            out.push(<h3 key={key()} id={slug(title)}>{inline(title, links, key())}</h3>);
            i++;
        } else if (trimmed.startsWith('> ')) {
            // > a note. "> **Warning:** …" (or GitHub's "> [!WARNING]") is shown in the warning colours.
            const note: string[] = [];
            for (; i < lines.length && lines[i].trim().startsWith('>'); i++) note.push(lines[i].trim().replace(/^>\s?/, ''));
            const warning = /^(\[!(WARNING|CAUTION|IMPORTANT)\]|\*\*Warning:?\*\*)/i.test(note[0]);
            if (/^\[!\w+\]$/.test(note[0])) note.shift();
            out.push(
                <div key={key()} className={`docs-note docs-note-${warning ? 'warning' : 'info'}`}>
                    <Icon name={warning ? 'shield' : 'message'} />
                    <div><GuideBlocks lines={note} prefix={key()} links={links} /></div>
                </div>,
            );
        } else if (trimmed.startsWith('|')) {
            const rows: string[][] = [];
            for (; i < lines.length && lines[i].trim().startsWith('|'); i++) {
                if (!/^\|[\s:|-]+\|$/.test(lines[i].trim())) rows.push(cells(lines[i]));
            }
            const [head, ...body] = rows;
            out.push(
                <div key={key()} className="docs-table">
                    <table>
                        <thead><tr>{head.map((c, j) => <th key={j}>{inline(c, links, `${key()}h${j}`)}</th>)}</tr></thead>
                        <tbody>{body.map((r, j) => <tr key={j}>{r.map((c, k) => <td key={k}>{inline(c, links, `${key()}r${j}c${k}`)}</td>)}</tr>)}</tbody>
                    </table>
                </div>,
            );
        } else if (/^(- |\d+\. )/.test(trimmed)) {
            const ordered = /^\d+\. /.test(trimmed);
            const items: string[][] = [];
            // Continuation lines lose the marker's width ("- " or "1. "), so a nested list keeps its own indent.
            let indent = /^ {1,2}/;
            while (i < lines.length) {
                const l = lines[i];
                const t = l.trim();
                if (/^(- |\d+\. )/.test(t) && !l.startsWith('  ')) {
                    const marker = /^(- |\d+\. )/.exec(t)![0];
                    indent = new RegExp(`^ {1,${marker.length}}`);
                    items.push([t.slice(marker.length)]);
                } else if (t && (l.startsWith('  ') || l.startsWith('\t'))) {
                    items[items.length - 1].push(l.replace(/^\t/, '').replace(indent, ''));
                } else if (!t && i + 1 < lines.length && lines[i + 1].startsWith('  ')) {
                    items[items.length - 1].push('');
                } else {
                    break;
                }
                i++;
            }
            const rendered = items.map((item, j) => {
                // The item's text runs on over its wrapped lines, up to a blank line or a nested block.
                let n = 1;
                while (n < item.length && item[n].trim() && !BLOCK_START.test(item[n].trim())) n++;
                const text = item.slice(0, n).map((l) => l.trim()).join(' ');
                const rest = item.slice(n);
                return <li key={j}>{inline(text, links, `${key()}i${j}`)}{rest.some((r) => r.trim()) && <GuideBlocks lines={rest} prefix={`${key()}i${j}`} links={links} />}</li>;
            });
            out.push(ordered ? <ol key={key()} className="docs-steps">{rendered}</ol> : <ul key={key()}>{rendered}</ul>);
        } else {
            const para: string[] = [];
            for (; i < lines.length; i++) {
                const t = lines[i].trim();
                if (!t || BLOCK_START.test(t)) break;
                para.push(t);
            }
            out.push(<p key={key()}>{inline(para.join(' '), links, key())}</p>);
        }
    }
    return <>{out}</>;
}

export default function Guide({ markdown, title, product, version, icons = {}, docsBase, appLink, searchPlaceholder, topSelector = '.topbar', search = true }: GuideProps) {
    const { intro, sections } = useMemo(() => splitGuide(markdown), [markdown]);
    const links = useMemo(() => ({ docsBase, appLink }), [docsBase, appLink]);
    const [q, setQ] = useState('');
    const term = q.trim().toLowerCase();
    const shown = term ? sections.filter((s) => `${s.title}\n${s.body.join('\n')}`.toLowerCase().includes(term)) : sections;
    const [active, setActive] = useState(sections[0]?.id ?? '');
    const toc = useRef<HTMLElement>(null);
    // After a jump the clicked section stays highlighted (one near the end may not reach the top) until the reader scrolls.
    const pinned = useRef<string | null>(null);
    const iconFor = (s: GuideSection) => icons[slug(plain(s.title))] ?? 'book';

    /** Where a heading should sit after a jump: just under the top bar (and the contents row on narrow screens). */
    const offset = useCallback(() => {
        const bar = document.querySelector(topSelector)?.getBoundingClientRect().bottom ?? 0;
        const list = toc.current;
        const row = list && getComputedStyle(list).display === 'flex' ? list.getBoundingClientRect().height : 0;
        return Math.max(bar, 0) + row + 16;
    }, [topSelector]);

    /** The section being read: the last one whose top has passed the reading line; the last one at the very bottom. */
    const inView = useCallback(() => {
        const ids = [...document.querySelectorAll<HTMLElement>('.docs-section')].map((el) => el.id);
        if (!ids.length) return '';
        if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) return ids[ids.length - 1];
        const line = offset() + 24;
        let current = ids[0];
        for (const id of ids) {
            const el = document.getElementById(id);
            if (el && el.getBoundingClientRect().top <= line) current = id;
        }
        return current;
    }, [offset]);

    const jump = useCallback((id: string, smooth: boolean) => {
        const el = document.getElementById(id);
        if (!el) return;
        const section = el.closest<HTMLElement>('.docs-section')?.id ?? id;
        window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - offset(), behavior: smooth ? 'smooth' : 'auto' });
        // Only the hash changes (keeping the router's history entry), so the browser does not jump again.
        history.replaceState(history.state, '', `#${id}`);
        pinned.current = section;
        setActive(section);
    }, [offset]);

    useEffect(() => {
        let frame = 0;
        const update = () => { frame = 0; if (!pinned.current) setActive(inView()); };
        const onScroll = () => { if (!frame) frame = requestAnimationFrame(update); };
        const unpin = () => { pinned.current = null; };
        const onHash = () => { const id = decodeURIComponent(window.location.hash.slice(1)); if (id) jump(id, false); };
        window.addEventListener('scroll', onScroll, { passive: true });
        window.addEventListener('resize', onScroll);
        window.addEventListener('hashchange', onHash);
        for (const type of ['wheel', 'touchstart', 'keydown', 'mousedown']) window.addEventListener(type, unpin, { passive: true });
        // Arriving with #section (a link from another page): go there once the page has laid out.
        const timer = window.setTimeout(() => (window.location.hash ? onHash() : update()), 50);
        return () => {
            window.clearTimeout(timer);
            if (frame) cancelAnimationFrame(frame);
            window.removeEventListener('scroll', onScroll);
            window.removeEventListener('resize', onScroll);
            window.removeEventListener('hashchange', onHash);
            for (const type of ['wheel', 'touchstart', 'keydown', 'mousedown']) window.removeEventListener(type, unpin);
        };
    }, [jump, inView]);

    // A search changes which sections are on the page.
    useEffect(() => { pinned.current = null; setActive(inView()); }, [term, inView]);

    // Keep the current entry in sight: in the sticky column, and in the sideways row on narrow screens.
    useEffect(() => {
        const list = toc.current;
        const link = list?.querySelector<HTMLElement>('[aria-current="true"]');
        if (!list || !link) return;
        if (getComputedStyle(list).display === 'flex') list.scrollTo({ left: link.offsetLeft - list.clientWidth / 2 + link.clientWidth / 2, behavior: 'smooth' });
        else if (link.offsetTop < list.scrollTop || link.offsetTop + link.offsetHeight > list.scrollTop + list.clientHeight) list.scrollTo({ top: link.offsetTop - list.clientHeight / 2 });
    }, [active]);

    // Every #link on the page (contents and links inside the text) scrolls with the right offset.
    const onClick = (event: MouseEvent<HTMLDivElement>) => {
        const link = (event.target as HTMLElement).closest('a');
        const href = link?.getAttribute('href') ?? '';
        if (!href.startsWith('#') || event.metaKey || event.ctrlKey || event.shiftKey) return;
        event.preventDefault();
        jump(decodeURIComponent(href.slice(1)), true);
    };

    return (
        <div className="docs" onClick={onClick}>
            <nav className="docs-toc" aria-label={`${title}: contents`} ref={toc}>
                <strong>Contents</strong>
                {shown.map((s) => (
                    <a key={s.id} href={`#${s.id}`} aria-current={active === s.id ? 'true' : undefined}><Icon name={iconFor(s)} />{plain(s.title)}</a>
                ))}
            </nav>
            <div className="docs-body">
                <header className="docs-intro">
                    <h2>{title}</h2>
                    <GuideBlocks lines={intro} prefix="intro" links={links} />
                    {product && version && <p>This guide describes {product} {version}.</p>}
                    {search && <label className="docs-search">
                        <Icon name="search" />
                        <span className="sr-only">Search the guide</span>
                        <input type="search" placeholder={searchPlaceholder ?? 'Search the guide'} value={q} onChange={(e) => setQ(e.target.value)} />
                    </label>}
                    {term && <p role="status">{shown.length ? `${shown.length} of ${sections.length} sections mention “${q.trim()}”.` : `Nothing in the guide mentions “${q.trim()}”.`}</p>}
                </header>
                {shown.map((s) => (
                    <section key={s.id} id={s.id} className="docs-section">
                        <h2><span className="account-section-icon"><Icon name={iconFor(s)} /></span>{plain(s.title)}</h2>
                        <GuideBlocks lines={s.body} prefix={s.id} links={links} />
                    </section>
                ))}
            </div>
        </div>
    );
}
