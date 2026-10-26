// Help: docs/USER-GUIDE.md, bundled into the console at build time (so it matches this version and works
// without internet), shown with RadiusOne's documentation layout (app.css, "Documentation"). The guide's
// Markdown is turned into React elements by the small renderer below, never into raw HTML.
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Empty } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { useShared } from '@/lib/auth';
import guide from '../../../docs/USER-GUIDE.md?raw';

const REPO_DOCS = 'https://github.com/Pingomni/dnsone/blob/main/docs/';

type Section = { id: string; title: string; body: string[] };

/** GitHub's heading anchors: "1. What DNSOne does" → "1-what-dnsone-does". */
function slug(text: string): string {
    return text.toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, '').trim().replace(/\s/g, '-');
}

/** The guide split at its "## " headings: the introduction, then one section each (the contents list is left out). */
function split(markdown: string): { intro: string[]; sections: Section[] } {
    const intro: string[] = [];
    const sections: Section[] = [];
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

function href(target: string): { url: string; external: boolean } {
    if (target.startsWith('#')) return { url: target, external: false };
    if (/^https?:\/\//.test(target)) return { url: target, external: true };
    return { url: REPO_DOCS + target, external: true };
}

/** `code`, **bold**, *italic* and [links](…) inside a line. */
function inline(text: string, key = ''): ReactNode[] {
    const out: ReactNode[] = [];
    const pattern = /`([^`]+)`|\*\*(.+?)\*\*|\*([^*\s][^*]*?)\*|\[([^\]]+)\]\(([^)\s]+)\)/g;
    let last = 0;
    let m: RegExpExecArray | null;
    let n = 0;
    while ((m = pattern.exec(text))) {
        if (m.index > last) out.push(text.slice(last, m.index));
        const k = `${key}-${n++}`;
        if (m[1] !== undefined) out.push(<code key={k}>{m[1]}</code>);
        else if (m[2] !== undefined) out.push(<strong key={k}>{inline(m[2], k)}</strong>);
        else if (m[3] !== undefined) out.push(<em key={k}>{inline(m[3], k)}</em>);
        else {
            const { url, external } = href(m[5]);
            out.push(<a key={k} href={url} {...(external ? { target: '_blank', rel: 'noreferrer' } : {})}>{inline(m[4], k)}</a>);
        }
        last = m.index + m[0].length;
    }
    if (last < text.length) out.push(text.slice(last));
    return out;
}

const cells = (row: string) => row.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());

/** Block-level Markdown: ### headings, paragraphs, - and 1. lists (with continuation lines), tables, code. */
function blocks(lines: string[], prefix: string): ReactNode[] {
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
            out.push(<pre key={key()} className="zone-preview">{code.join('\n')}</pre>);
        } else if (trimmed.startsWith('### ')) {
            const title = trimmed.slice(4);
            out.push(<h3 key={key()} id={slug(title)}>{inline(title, key())}</h3>);
            i++;
        } else if (trimmed.startsWith('|')) {
            const rows: string[][] = [];
            for (; i < lines.length && lines[i].trim().startsWith('|'); i++) {
                if (!/^\|[\s:|-]+\|$/.test(lines[i].trim())) rows.push(cells(lines[i]));
            }
            const [head, ...body] = rows;
            out.push(
                <div key={key()} className="docs-table">
                    <table>
                        <thead><tr>{head.map((c, j) => <th key={j}>{inline(c, `${key()}h${j}`)}</th>)}</tr></thead>
                        <tbody>{body.map((r, j) => <tr key={j}>{r.map((c, k) => <td key={k}>{inline(c, `${key()}r${j}c${k}`)}</td>)}</tr>)}</tbody>
                    </table>
                </div>,
            );
        } else if (/^(- |\d+\. )/.test(trimmed)) {
            const ordered = /^\d+\. /.test(trimmed);
            const items: string[][] = [];
            while (i < lines.length) {
                const l = lines[i];
                const t = l.trim();
                if (/^(- |\d+\. )/.test(t) && !l.startsWith('  ')) {
                    items.push([t.replace(/^(- |\d+\. )/, '')]);
                } else if (t && (l.startsWith('  ') || l.startsWith('\t'))) {
                    items[items.length - 1].push(l.replace(/^ {2,4}/, ''));
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
                while (n < item.length && item[n].trim() && !/^(- |\d+\. |\||```)/.test(item[n].trim())) n++;
                const text = item.slice(0, n).map((l) => l.trim()).join(' ');
                const rest = item.slice(n);
                return <li key={j}>{inline(text, `${key()}i${j}`)}{rest.some((r) => r.trim()) && blocks(rest, `${key()}i${j}`)}</li>;
            });
            out.push(ordered ? <ol key={key()} className="docs-steps">{rendered}</ol> : <ul key={key()}>{rendered}</ul>);
        } else {
            const para: string[] = [];
            for (; i < lines.length; i++) {
                const t = lines[i].trim();
                if (!t || /^(- |\d+\. |\||```|### )/.test(t)) break;
                para.push(t);
            }
            out.push(<p key={key()}>{inline(para.join(' '), key())}</p>);
        }
    }
    return out;
}

export default function Help() {
    const { appVersion } = useShared();
    const { intro, sections } = useMemo(() => split(guide), []);
    const [q, setQ] = useState('');
    const [current, setCurrent] = useState(window.location.hash.slice(1) || sections[0]?.id);
    const term = q.trim().toLowerCase();
    const shown = term ? sections.filter((s) => `${s.title}\n${s.body.join('\n')}`.toLowerCase().includes(term)) : sections;

    // A link to /help#section (or a section link inside the guide) scrolls there once the page is drawn.
    useEffect(() => {
        const go = () => {
            const id = decodeURIComponent(window.location.hash.slice(1));
            if (!id) return;
            setCurrent(sections.find((s) => s.id === id || s.body.some((l) => l.startsWith('### ') && slug(l.slice(4)) === id))?.id ?? id);
            // After the router has restored or reset the scroll position for this navigation.
            window.setTimeout(() => document.getElementById(id)?.scrollIntoView(), 50);
        };
        go();
        window.addEventListener('hashchange', go);
        window.addEventListener('popstate', go);
        return () => {
            window.removeEventListener('hashchange', go);
            window.removeEventListener('popstate', go);
        };
    }, [sections]);

    return (
        <AppLayout title="Help">
            <div className="docs">
                <nav className="docs-toc" aria-label="Guide sections">
                    <strong>User guide</strong>
                    {shown.map((s) => (
                        <a key={s.id} href={`#${s.id}`} aria-current={s.id === current ? 'true' : undefined} onClick={() => setCurrent(s.id)}>{s.title.replace(/^\d+\.\s*/, '')}</a>
                    ))}
                </nav>
                <div className="docs-body">
                    <section className="docs-intro">
                        <h2>DNSOne user guide</h2>
                        {blocks(intro, 'intro')}
                        <p>This guide describes DNSOne {appVersion}.</p>
                        <label className="list-search">
                            <span>Search the guide</span>
                            <input type="search" placeholder="e.g. DNSSEC, quota, firewall" value={q} onChange={(e) => setQ(e.target.value)} />
                        </label>
                        {term && <p>{shown.length} of {sections.length} sections mention “{q.trim()}”.</p>}
                    </section>
                    {shown.map((s) => (
                        <section key={s.id} id={s.id} className="docs-section">
                            <h2>{s.title}</h2>
                            {blocks(s.body, s.id)}
                        </section>
                    ))}
                    {!shown.length && <Empty>Nothing in the guide mentions “{q.trim()}”.</Empty>}
                </div>
            </div>
        </AppLayout>
    );
}
