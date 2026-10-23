import { Link, router, usePage } from '@inertiajs/react';
import { useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { useToast } from '@/components/dns/feedback';
import { LivePanel } from '@/components/LivePanel';
import { DataTable } from '@/components/table';
import { Badge, Empty, HealthItem, ListPanel, Panel, RowActions } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { post, searchOf, useApi, type ApiError } from '@/lib/api';
import { useCan, useShared } from '@/lib/auth';
import { query } from '@/lib/format';

type Row = { id: number; time: string; client: string; qname: string; qtype: string; rcode: string; status: 'ok' | 'blocked' | 'allowed'; latency_ms: number | null };
type LogResult = { rows: Row[]; next_before: number | null; window_minutes: number | null };
type Item = { item: string; hits: number };
type Top = { dimension: string; hours: number; rows: Item[] };
type Collector = { node?: string; last_message_at?: string; receiving: boolean };
type Summary = {
    hours: number; total: number; status: Record<'ok' | 'blocked' | 'allowed', number>; blocked_ratio: number | null;
    qtype: Item[]; rcode: Item[]; mode: string; retention_hours: number; max_rows: number; oldest_row: string | null; collectors: Collector[];
};
type HistoryPoint = { time: string; total: number; ok: number; blocked: number; allowed: number };
type Filters = { domain: string; qname: string; client: string; status: string; qtype: string; rcode: string; minutes: string };

const FILTER_KEYS: (keyof Filters)[] = ['domain', 'qname', 'client', 'status', 'qtype', 'rcode', 'minutes'];
const STATUS_TONE = { ok: '', blocked: 'danger', allowed: 'success' } as const;
const WINDOWS: [string, string][] = [['', 'Any time'], ['15', 'Last 15 minutes'], ['60', 'Last hour'], ['360', 'Last 6 hours'], ['1440', 'Last 24 hours'], ['10080', 'Last 7 days']];
const PERIODS: [number, string][] = [[1, '1 hour'], [24, '24 hours'], [168, '7 days'], [720, '30 days']];

const logHref = (params: Partial<Filters>) => `/queries${query(params)}`;

function DomainActions({ domain }: { domain: string }) {
    const confirm = useConfirm();
    const toast = useToast();
    const add = async (action: 'block' | 'allow') => {
        const ok = await confirm({
            title: `${action === 'block' ? 'Block' : 'Allow'} ${domain}?`,
            message: action === 'block'
                ? `Every client gets a blocked answer for ${domain} and the names below it.`
                : `${domain} is answered normally even when a blocklist lists it.`,
            confirmLabel: action === 'block' ? 'Block domain' : 'Allow domain',
        });
        if (!ok) return;
        try {
            await post('/api/rpz/rules', { pattern: domain, action, target: null, comment: 'Added from the query log' });
            toast(`${action === 'block' ? 'Blocked' : 'Allowed'} ${domain}. The Recursor picks it up in a few seconds.`);
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    return (
        <RowActions label={`Actions for ${domain}`}>
            <button type="button" onClick={() => void add('block')}>Block this domain</button>
            <button type="button" onClick={() => void add('allow')}>Allow this domain</button>
            <Link href={`/blocking?tab=rules&q=${encodeURIComponent(domain)}`}>Find matching rules</Link>
        </RowActions>
    );
}

function LogTable({ rows, manage }: { rows: Row[]; manage: boolean }) {
    return (
        <DataTable
            rows={rows}
            rowKey={(r) => r.id}
            serverPaginated
            exportRows
            resetHref="/queries"
            emptyText="No queries match these filters."
            columns={[
                { header: 'Time', cell: (r) => <span className="mono">{r.time.slice(5)}</span> },
                { header: 'Client', cell: (r) => <Link className="mono" href={logHref({ client: r.client })} title="Show only this client">{r.client}</Link> },
                { header: 'Domain', className: 'cell-wrap', cell: (r) => <Link className="mono" href={logHref({ qname: r.qname })} title="Show only this name">{r.qname}</Link> },
                { header: 'Type', cell: (r) => r.qtype },
                { header: 'Reply', cell: (r) => (r.rcode === 'NOERROR' ? r.rcode : <Badge tone="warning">{r.rcode}</Badge>) },
                { header: 'Status', cell: (r) => <Badge tone={STATUS_TONE[r.status]}>{r.status}</Badge> },
                { header: 'Time taken', cell: (r) => (r.latency_ms === null ? '-' : `${r.latency_ms} ms`) },
                ...(manage ? [{ header: '', noExport: true, cell: (r: Row) => <DomainActions domain={r.qname} /> }] : []),
            ]}
        />
    );
}

function QueryLog({ params }: { params: URLSearchParams }) {
    const can = useCan();
    const filters = Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? ''])) as Filters;
    const before = params.get('before') ?? '';
    const url = `/api/queries${query({ ...filters, before })}`;
    const { data, error } = useApi<LogResult>(url);
    const [values, setValues] = useState(filters);
    const apply = (next: Filters) => router.get('/queries', Object.fromEntries(Object.entries(next).filter(([, v]) => v)), { preserveScroll: true });
    const set = (key: keyof Filters, value: string, now = false) => {
        const next = { ...values, [key]: value };
        setValues(next);
        if (now) apply(next);
    };
    const filtered = Object.values(filters).some(Boolean);
    const clientGroup = useApi<{ group: { id: number; name: string; blocking: boolean }; network: string | null }>(
        filters.client && can('rpz.view') ? `/api/groups/lookup?client=${encodeURIComponent(filters.client)}` : null,
    ).data;
    const manage = can('rpz.manage');
    const scope = [filters.client && `client ${filters.client}`, filters.qname && filters.qname, filters.domain && `names containing “${filters.domain}”`].filter(Boolean).join(', ');

    return (
        <ListPanel
            title={scope ? `Queries from ${scope}` : 'Every query, newest first'}
            description={data?.window_minutes && filters.domain && !filters.minutes ? 'A search by part of a name looks at the last hour unless you choose a period.' : 'Click a client or a domain to see only its queries.'}
        >
            <form className="toolbar list-filterbar" role="search" onSubmit={(e) => { e.preventDefault(); apply(values); }}>
                <label className="list-search"><span>Domain contains</span><input type="search" placeholder="example.com" spellCheck={false} value={values.domain} onChange={(e) => set('domain', e.target.value)} /></label>
                <label className="list-filter"><span>Client</span><input type="search" placeholder="IP address" spellCheck={false} value={values.client} onChange={(e) => set('client', e.target.value)} /></label>
                <label className="list-filter"><span>Status</span>
                    <select value={values.status} onChange={(e) => set('status', e.target.value, true)}>
                        <option value="">Any</option><option value="ok">ok</option><option value="blocked">blocked</option><option value="allowed">allowed</option>
                    </select>
                </label>
                <label className="list-filter"><span>Type</span><input placeholder="A, AAAA…" spellCheck={false} value={values.qtype} onChange={(e) => set('qtype', e.target.value)} /></label>
                <label className="list-filter"><span>Reply</span><input placeholder="NXDOMAIN…" spellCheck={false} value={values.rcode} onChange={(e) => set('rcode', e.target.value)} /></label>
                <label className="list-filter"><span>Period</span>
                    <select value={values.minutes} onChange={(e) => set('minutes', e.target.value, true)}>
                        {WINDOWS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
                    </select>
                </label>
                <div className="list-filter-buttons">
                    <button>Filter</button>
                    {filtered && <Link className="button" href="/queries">Clear</Link>}
                </div>
            </form>
            {clientGroup && (
                <div className="toolbar query-scope">
                    Client group <Link href={`/groups?id=${clientGroup.group.id}`}>{clientGroup.group.name}</Link>
                    {clientGroup.network && <span className="mono">({clientGroup.network})</span>}
                    {!clientGroup.group.blocking && <Badge tone="warning">no ad-blocking</Badge>}
                </div>
            )}
            {filters.qname && <div className="toolbar query-scope">Exact name <strong className="mono">{filters.qname}</strong>{manage && <DomainActions domain={filters.qname} />}</div>}
            {error && <div className="flash danger">{error.message}</div>}
            {data && (before ? (
                <LogTable rows={data.rows} manage={manage} />
            ) : (
                // The newest page follows new queries; it pauses while the pointer or focus is in it.
                <LivePanel title="Live" url={url} interval={10} initial={data} className="live-bare" render={(d) => <LogTable rows={d.rows} manage={manage} />} />
            ))}
            {data && (
                <nav className="pagination server-pagination" aria-label="Query log pages">
                    <span className="pagination-summary">{data.rows.length} queries on this page</span>
                    {before && <Link className="button" href={logHref(filters)} preserveScroll>Newest</Link>}
                    {data.next_before
                        ? <Link className="button" href={`/queries${query({ ...filters, before: data.next_before })}`} preserveScroll>Older</Link>
                        : <button type="button" disabled>Older</button>}
                </nav>
            )}
        </ListPanel>
    );
}

/** Queries per day over weeks (the hourly counters, kept 35 days), answered and blocked. */
function History() {
    const { data, error } = useApi<{ series: HistoryPoint[] }>('/api/queries/history?days=30');
    if (error) return <div className="flash danger">{error.message}</div>;
    if (!data) return null;
    const max = Math.max(1, ...data.series.map((d) => d.total));
    return (
        <Panel title="History, last 30 days">
            {data.series.length ? (
                <>
                    <div className="hour-bars" style={{ '--bars': data.series.length } as React.CSSProperties} role="img" aria-label="Queries and blocked queries per day, last 30 days">
                        {data.series.map((d) => (
                            <div key={d.time} title={`${d.time} UTC: ${d.total.toLocaleString()} queries, ${d.blocked.toLocaleString()} blocked`}>
                                <span style={{ height: `${((d.total - d.blocked) / max) * 100}%` }} />
                                <span className="blocked" style={{ height: `${(d.blocked / max) * 100}%` }} />
                            </div>
                        ))}
                    </div>
                    <div className="hour-legend"><span><i />Answered</span><span><i className="blocked" />Blocked</span><span>Peak {max.toLocaleString()} queries / day</span></div>
                </>
            ) : <Empty>No history yet: dnsone-querylog writes it every minute.</Empty>}
        </Panel>
    );
}

function TopList({ title, dimension, hours, href, noun }: { title: string; dimension: string; hours: number; href: (item: string) => string; noun: string }) {
    const { data, error } = useApi<Top>(`/api/queries/top?dimension=${dimension}&hours=${hours}&limit=15`);
    const max = Math.max(1, ...(data?.rows.map((r) => r.hits) ?? []));
    return (
        <Panel title={title}>
            {error && <div className="flash danger">{error.message}</div>}
            {data && (data.rows.length ? (
                <DataTable
                    rows={data.rows}
                    rowKey={(r) => r.item}
                    columns={[
                        { header: noun, className: 'cell-wrap', cell: (r) => <Link className="mono" href={href(r.item)}>{r.item}</Link> },
                        { header: 'Queries', cell: (r) => <span className="top-hits"><meter min={0} max={max} value={r.hits} aria-hidden="true" />{r.hits.toLocaleString()}</span> },
                    ]}
                />
            ) : <Empty>Nothing in this period.</Empty>)}
        </Panel>
    );
}

function Breakdown({ title, items, total, href }: { title: string; items: Item[]; total: number; href: (item: string) => string }) {
    return (
        <Panel title={title}>
            {items.length ? (
                <div className="health-grid">
                    {items.map((i) => (
                        <HealthItem key={i.item} label={i.item} value={<Link href={href(i.item)}>{i.hits.toLocaleString()} <span className="list-subline">{total ? `${((100 * i.hits) / total).toFixed(1)}%` : ''}</span></Link>} />
                    ))}
                </div>
            ) : <Empty>Nothing in this period.</Empty>}
        </Panel>
    );
}

function TopLists({ hours, data }: { hours: number; data: Summary | null }) {
    return (
        <>
            <nav className="segmented" aria-label="Period">
                {PERIODS.map(([h, label]) => <Link key={h} href={`/queries?view=top&hours=${h}`} aria-current={h === hours ? 'page' : undefined} preserveScroll>{label}</Link>)}
            </nav>
            <History />
            {data && (
                <div className="dashboard-grid">
                    <TopList title="Top permitted domains" dimension="domain" hours={hours} noun="Domain" href={(d) => logHref({ qname: d })} />
                    <TopList title="Top blocked domains" dimension="blocked" hours={hours} noun="Domain" href={(d) => logHref({ qname: d, status: 'blocked' })} />
                    <TopList title="Top clients" dimension="client" hours={hours} noun="Client" href={(c) => logHref({ client: c })} />
                    <TopList title="Clients with the most blocked queries" dimension="client_blocked" hours={hours} noun="Client" href={(c) => logHref({ client: c, status: 'blocked' })} />
                    <Breakdown title="Query types" items={data.qtype} total={data.total} href={(t) => logHref({ qtype: t, minutes: String(Math.min(hours, 168) * 60) })} />
                    <Breakdown title="Reply codes" items={data.rcode} total={data.total} href={(r) => logHref({ rcode: r, minutes: String(Math.min(hours, 168) * 60) })} />
                </div>
            )}
        </>
    );
}

function SummaryStrip({ hours, data }: { hours: number; data: Summary }) {
    const silent = data.collectors.length === 0 || data.collectors.every((c) => !c.receiving);
    return (
        <Panel className="query-summary">
            {silent && (
                <div className="flash warning">
                    The query log collector has received nothing in the last 5 minutes. Check <span className="mono">dnsone-querylog.service</span> and the Recursor's protobuf export.
                </div>
            )}
            <div className="health-grid">
                <HealthItem label={`Queries, last ${PERIODS.find(([h]) => h === hours)?.[1] ?? `${hours} hours`}`} value={data.total.toLocaleString()} />
                <HealthItem label="Blocked" value={`${data.status.blocked.toLocaleString()}${data.blocked_ratio !== null ? ` (${data.blocked_ratio}%)` : ''}`} />
                <HealthItem label="Allowed by a rule" value={data.status.allowed.toLocaleString()} />
                <HealthItem label="Kept" value={`${data.retention_hours >= 48 ? `${Math.round(data.retention_hours / 24)} days` : `${data.retention_hours} hours`}, up to ${data.max_rows.toLocaleString()} rows`} />
                <HealthItem label="Oldest entry" value={data.oldest_row ? <span className="mono">{data.oldest_row.slice(0, 16)}</span> : '-'} />
            </div>
        </Panel>
    );
}

export default function Queries() {
    const { url } = usePage();
    const { clock } = useShared();
    const params = searchOf(url);
    const view = params.get('view') === 'top' ? 'top' : 'log';
    const hours = PERIODS.some(([h]) => String(h) === params.get('hours')) ? Number(params.get('hours')) : 24;
    const summary = useApi<Summary>(`/api/queries/summary?hours=${hours}`);

    return (
        <AppLayout title="Query log">
            <div className="clean-list">
                <nav className="segmented" aria-label="Query views">
                    <Link href="/queries" aria-current={view === 'log' ? 'page' : undefined}>Log</Link>
                    <Link href={`/queries?view=top&hours=${hours}`} aria-current={view === 'top' ? 'page' : undefined}>Top lists</Link>
                </nav>
                {summary.error && <div className="flash danger">{summary.error.message}</div>}
                {summary.data && <SummaryStrip hours={hours} data={summary.data} />}
                {view === 'log' ? <QueryLog key={url} params={params} /> : <TopLists hours={hours} data={summary.data} />}
                <p className="list-subline">Times are in {clock.timezone}.</p>
            </div>
        </AppLayout>
    );
}
