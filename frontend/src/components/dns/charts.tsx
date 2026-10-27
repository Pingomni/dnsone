// Charts for the dashboard, drawn as SVG in the console's theme (no chart library). Colours are the --viz-*
// tokens in dnsone.css: series take them in a fixed order, "Other" is always the neutral grey, and every
// chart names its series in text (legend, tooltip, table), never by colour alone.
import { useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { formatInZone, useServerTimezone } from '@/lib/clock';

export type SeriesKey = { key: string; label: string; color: string };
type Point = Record<string, number | string>;

const nf = (n: number) => n.toLocaleString();
const compact = (n: number) => (n >= 10_000 ? `${Math.round(n / 1000)}k` : n >= 1000 ? `${(n / 1000).toFixed(1).replace(/\.0$/, '')}k` : String(Math.round(n)));

/** The fixed categorical order; slot n of a chart is always the same colour. */
export function seriesColor(index: number, label?: string): string {
    return label === 'Other' ? 'var(--viz-other)' : `var(--viz-${(index % 8) + 1})`;
}

/** Round gridline values: a step of 1, 2 or 5 times a power of ten, about four of them up to the peak. */
function niceTicks(peak: number): number[] {
    if (peak <= 0) return [0, 1];
    const raw = peak / 4;
    const power = 10 ** Math.floor(Math.log10(raw));
    const step = ([1, 2, 5, 10].map((m) => m * power).find((m) => m >= raw) ?? 10 * power);
    const out = [];
    for (let v = 0; v < peak + step; v += step) out.push(v);
    return out;
}

function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
    const ref = useRef<T>(null);
    const [width, setWidth] = useState(0);
    useLayoutEffect(() => {
        const node = ref.current;
        if (!node) return undefined;
        const observer = new ResizeObserver(([entry]) => setWidth(Math.round(entry.contentRect.width)));
        observer.observe(node);
        return () => observer.disconnect();
    }, []);
    return [ref, width];
}

export function Legend({ items }: { items: { label: string; color: string; value?: ReactNode }[] }) {
    return (
        <ul className="viz-legend">
            {items.map((i) => (
                <li key={i.label}><i style={{ background: i.color }} aria-hidden="true" /><span>{i.label}</span>{i.value !== undefined && <strong>{i.value}</strong>}</li>
            ))}
        </ul>
    );
}

/**
 * Stacked areas over time with a crosshair and a tooltip for the hovered moment. `time` holds naive UTC
 * ISO minutes ("2026-10-27T14:10"); labels are in the server's timezone.
 */
export function AreaChart({ points, keys, label, height = 220, step }: { points: Point[]; keys: SeriesKey[]; label: string; height?: number; step: string }) {
    const timeZone = useServerTimezone();
    const [box, width] = useWidth<HTMLDivElement>();
    const [hover, setHover] = useState<number | null>(null);
    const pad = { top: 10, right: 12, bottom: 24, left: 44 };
    const w = Math.max(0, width - pad.left - pad.right);
    const h = height - pad.top - pad.bottom;
    const times = points.map((p) => Date.parse(`${p.time}Z`));
    const totals = points.map((p) => keys.reduce((sum, k) => sum + (Number(p[k.key]) || 0), 0));
    const ticks = niceTicks(Math.max(0, ...totals));
    const max = ticks[ticks.length - 1];
    const x = (i: number) => pad.left + (points.length > 1 ? (i / (points.length - 1)) * w : 0);
    const y = (v: number) => pad.top + h - (v / max) * h;
    const fmt = (ms: number, opts: Intl.DateTimeFormatOptions) => formatInZone(ms, timeZone, { hour12: false, ...opts });

    // Cumulative tops, bottom series first.
    const stacks: number[][] = [];
    keys.forEach((k, s) => stacks.push(points.map((p, i) => (s ? stacks[s - 1][i] : 0) + (Number(p[k.key]) || 0))));
    const line = (vals: number[]) => vals.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join('');
    const area = (s: number) => {
        const top = stacks[s];
        const base = s ? stacks[s - 1] : points.map(() => 0);
        return `${line(top)}L${base.map((v, i) => `${x(base.length - 1 - i).toFixed(1)},${y(base[base.length - 1 - i]).toFixed(1)}`).join('L')}Z`;
    };
    // A time label every 3 hours on the hour (every 6 on a narrow chart).
    const every = (w < 420 ? 6 : 3) * 3600_000;
    const xTicks = times.map((t, i) => [t, i] as const).filter(([t]) => t % every === 0);

    const onMove = (e: React.PointerEvent<SVGRectElement>) => {
        const rect = e.currentTarget.getBoundingClientRect();
        const i = Math.round(((e.clientX - rect.left) / Math.max(1, rect.width)) * (points.length - 1));
        setHover(Math.min(points.length - 1, Math.max(0, i)));
    };
    const hp = hover !== null ? points[hover] : null;
    const tipLeft = hover !== null ? x(hover) : 0;

    return (
        <figure className="viz" aria-label={label}>
            <div ref={box} className="viz-plot" style={{ height }}>
                {width > 0 && (
                    <svg width={width} height={height} role="img" aria-label={label}>
                        <g className="viz-grid">
                            {ticks.map((t) => (
                                <g key={t}>
                                    <line x1={pad.left} x2={pad.left + w} y1={y(t)} y2={y(t)} />
                                    <text x={pad.left - 8} y={y(t)} dy="0.32em" textAnchor="end">{compact(t)}</text>
                                </g>
                            ))}
                            {xTicks.map(([t, i]) => (
                                <text key={t} x={x(i)} y={height - 6} textAnchor="middle">{fmt(t, { hour: '2-digit', minute: '2-digit' })}</text>
                            ))}
                        </g>
                        {keys.map((k, s) => <path key={k.key} d={area(s)} fill={k.color} className="viz-area" />)}
                        {keys.map((k, s) => <path key={k.key} d={line(stacks[s])} stroke={k.color} className="viz-line" />)}
                        {hover !== null && (
                            <g className="viz-cross">
                                <line x1={x(hover)} x2={x(hover)} y1={pad.top} y2={pad.top + h} />
                                {keys.map((k, s) => <circle key={k.key} cx={x(hover)} cy={y(stacks[s][hover])} r={4} fill={k.color} />)}
                            </g>
                        )}
                        <rect x={pad.left} y={pad.top} width={w} height={h} fill="transparent" onPointerMove={onMove} onPointerDown={onMove} onPointerLeave={() => setHover(null)} />
                    </svg>
                )}
                {hp && hover !== null && (
                    <div className="viz-tip" style={{ left: tipLeft, '--flip': tipLeft > width / 2 ? 1 : 0 } as CSSProperties} role="status">
                        <div className="viz-tip-title">{fmt(times[hover], { weekday: 'short', hour: '2-digit', minute: '2-digit' })} · {step}</div>
                        {[...keys].reverse().map((k) => (
                            <div key={k.key} className="viz-tip-row"><i style={{ background: k.color }} /><span>{k.label}</span><strong>{nf(Number(hp[k.key]) || 0)}</strong></div>
                        ))}
                        {keys.length > 1 && <div className="viz-tip-row viz-tip-total"><span>Total</span><strong>{nf(totals[hover])}</strong></div>}
                    </div>
                )}
            </div>
            <details className="viz-table">
                <summary>Show as a table</summary>
                <div className="viz-table-scroll">
                    <table>
                        <thead><tr><th>Time</th>{keys.map((k) => <th key={k.key}>{k.label}</th>)}</tr></thead>
                        <tbody>
                            {points.map((p, i) => (totals[i] ? (
                                <tr key={String(p.time)}><td>{fmt(times[i], { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })}</td>{keys.map((k) => <td key={k.key}>{nf(Number(p[k.key]) || 0)}</td>)}</tr>
                            ) : null))}
                        </tbody>
                    </table>
                </div>
            </details>
        </figure>
    );
}

/** Shares of a whole, as a ring with the total inside, and a legend with counts and percentages. */
export function Donut({ rows, label, center, names = {}, colors = {} }: {
    rows: { item: string; hits: number }[]; label: string; center: string; names?: Record<string, string>;
    /** Fixed colours for items that have one elsewhere (Answered, Blocked), so they match across charts. */
    colors?: Record<string, string>;
}) {
    const colorOf = (i: number, item: string) => colors[item] ?? seriesColor(i, item);
    const [hover, setHover] = useState<number | null>(null);
    const total = rows.reduce((s, r) => s + r.hits, 0);
    const size = 168;
    const r = 66;
    const stroke = 22;
    const circumference = 2 * Math.PI * r;
    const gap = rows.length > 1 ? 2 : 0;
    let offset = 0;
    const slices = rows.map((row, i) => {
        const length = total ? (row.hits / total) * circumference : 0;
        const slice = { row, i, color: colorOf(i, row.item), dash: Math.max(0, length - gap), offset };
        offset += length;
        return slice;
    });
    const pct = (n: number) => (total ? `${((100 * n) / total).toFixed(n / total < 0.1 ? 1 : 0)}%` : '–');
    const shown = hover !== null ? rows[hover] : null;
    return (
        <figure className="viz viz-donut" aria-label={label}>
            <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} role="img" aria-label={`${label}: ${rows.map((x) => `${names[x.item] ?? x.item} ${pct(x.hits)}`).join(', ')}`}>
                <circle cx={size / 2} cy={size / 2} r={r} className="viz-donut-track" strokeWidth={stroke} fill="none" />
                {slices.map((s) => (
                    <circle key={s.row.item} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={s.color} strokeWidth={hover === s.i ? stroke + 6 : stroke}
                        strokeDasharray={`${s.dash} ${circumference - s.dash}`} strokeDashoffset={-s.offset} transform={`rotate(-90 ${size / 2} ${size / 2})`}
                        className="viz-slice" onPointerEnter={() => setHover(s.i)} onPointerLeave={() => setHover(null)} />
                ))}
                <text x="50%" y="47%" textAnchor="middle" className="viz-donut-value">{shown ? pct(shown.hits) : compact(total)}</text>
                <text x="50%" y="60%" textAnchor="middle" className="viz-donut-label">{shown ? (names[shown.item] ?? shown.item) : center}</text>
            </svg>
            <ul className="viz-legend viz-legend-list">
                {rows.map((row, i) => (
                    <li key={row.item} className={hover === i ? 'active' : undefined} onPointerEnter={() => setHover(i)} onPointerLeave={() => setHover(null)}>
                        <i style={{ background: colorOf(i, row.item) }} aria-hidden="true" />
                        <span>{names[row.item] ?? row.item}</span>
                        <strong>{nf(row.hits)}</strong>
                        <em>{pct(row.hits)}</em>
                    </li>
                ))}
            </ul>
        </figure>
    );
}

/** A ranked list with a bar for each count (the longest bar is the first row). */
export function BarList({ rows, color, empty, href }: { rows: { item: string; hits: number }[]; color: string; empty: string; href?: (item: string) => string }) {
    if (!rows.length) return <p className="hint panel-text">{empty}</p>;
    const max = Math.max(...rows.map((r) => r.hits));
    return (
        <ol className="viz-bars">
            {rows.map((r) => (
                <li key={r.item} title={`${r.item}: ${nf(r.hits)}`}>
                    <span className="viz-bar" style={{ width: `${(r.hits / max) * 100}%`, background: color }} aria-hidden="true" />
                    {href ? <a href={href(r.item)}>{r.item}</a> : <span>{r.item}</span>}
                    <strong>{nf(r.hits)}</strong>
                </li>
            ))}
        </ol>
    );
}
