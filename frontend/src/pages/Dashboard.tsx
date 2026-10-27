import { Link } from '@inertiajs/react';
import { AreaChart, BarList, Donut, Legend, seriesColor, type SeriesKey } from '@/components/dns/charts';
import Icon from '@/components/Icon';
import { LivePanel } from '@/components/LivePanel';
import { MetricCards, type Metric } from '@/components/metrics';
import { DataTable } from '@/components/table';
import { Badge, Empty, Panel, Time } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { useApi } from '@/lib/api';
import { useCan, useShared } from '@/lib/auth';

type Hour = { hour: string; queries: number; blocked: number };
type Recent = { id: number; actor: string; action: string; entity: string; summary: string; created_at: string };
type Share = { item: string; hits: number };
type Traffic = {
    clients: { keys: string[]; series: ({ hour: string } & Record<string, number | string>)[] };
    qtype: Share[]; rcode: Share[]; status: Share[]; top_domains: Share[]; top_blocked: Share[]; top_clients: Share[];
};
type DashboardData = { metrics: Metric[]; series: Hour[]; recent: Recent[]; traffic: Traffic | null };
type Check = { name: string; status: 'ok' | 'warning' | 'error'; detail: string };
type Health = { status: string; checks: Check[] };
type Alert = { key: string; severity: 'error' | 'warning'; title: string; detail: string; since: string; node: string };

// Service health, grouped; a check not listed here goes to Server.
const GROUPS: [string, string[]][] = [
    ['DNS service', ['BIND (DNS)', 'BIND (rndc)', 'PowerDNS Recursor', 'dnsdist', 'Encrypted DNS', 'Dynamic DNS']],
    ['DNSOne', ['Zone publishing', 'RPZ', 'Client policies', 'DNS server settings', 'Query log', 'Query log export', 'Firewall']],
    ['Server', ['MySQL']],
];
const MARK = { ok: ['✓', 'ok'], warning: ['!', 'warning'], error: ['×', 'error'] } as const;

function HealthBoard({ health }: { health: Health }) {
    const problems = health.checks.filter((c) => c.status !== 'ok');
    const errors = problems.filter((c) => c.status === 'error').length;
    const grouped = GROUPS.map(([title, names]) => [title, health.checks.filter((c) => names.includes(c.name))] as const);
    const known = new Set(GROUPS.flatMap(([, names]) => names));
    grouped[2][1].push(...health.checks.filter((c) => !known.has(c.name)));
    const tone = errors ? 'error' : problems.length ? 'warning' : 'ok';
    return (
        <div className="health-board">
            <p className={`health-summary ${tone}`} role="status">
                <span className={`health-mark ${tone}`} aria-hidden="true">{MARK[tone][0]}</span>
                {problems.length
                    ? <><strong>{errors ? `${errors} problem${errors === 1 ? '' : 's'}` : ''}{errors && problems.length > errors ? ', ' : ''}{problems.length > errors ? `${problems.length - errors} warning${problems.length - errors === 1 ? '' : 's'}` : ''}</strong>
                        <span>{problems.map((c) => c.name).join(', ')}</span></>
                    : <><strong>All {health.checks.length} checks pass</strong><span>DNS answers, zones publish and ad-blocking is current.</span></>}
            </p>
            <div className="health-groups">
                {grouped.filter(([, checks]) => checks.length).map(([title, checks]) => (
                    <section key={title} aria-label={title}>
                        <h3>{title}</h3>
                        <ul>
                            {checks.map((c) => (
                                <li key={c.name} className={c.status}>
                                    <span className={`health-mark ${c.status}`} role="img" aria-label={MARK[c.status][1]}>{MARK[c.status][0]}</span>
                                    <span className="health-name">{c.name}</span>
                                    <span className="health-detail" title={c.detail}>{c.detail}</span>
                                </li>
                            ))}
                        </ul>
                    </section>
                ))}
            </div>
        </div>
    );
}

const QUERY_KEYS: SeriesKey[] = [
    { key: 'answered', label: 'Answered', color: 'var(--viz-answered)' },
    { key: 'blocked', label: 'Blocked', color: 'var(--viz-blocked)' },
];
const STATUS_NAMES: Record<string, string> = { ok: 'Answered', blocked: 'Blocked', allowed: 'Allowed by a rule', legal: 'Court order' };
const STATUS_COLORS: Record<string, string> = { ok: 'var(--viz-answered)', blocked: 'var(--viz-blocked)', allowed: 'var(--viz-1)', legal: 'var(--viz-7)' };

function QueriesChart({ series }: { series: Hour[] }) {
    if (!series.some((h) => h.queries)) return <Empty>No query statistics yet. They appear a few minutes after dnsone-stats.timer starts.</Empty>;
    // The first and the current bucket hold part of their 10 minutes only: drawn, they dip at both ends.
    const points = series.slice(1, -1).map((h) => ({ time: h.hour, answered: Math.max(0, h.queries - h.blocked), blocked: Math.min(h.blocked, h.queries) }));
    const total = series.reduce((s, h) => s + h.queries, 0);
    const blocked = series.reduce((s, h) => s + Math.min(h.blocked, h.queries), 0);
    return (
        <>
            <Legend items={[
                { label: 'Answered', color: 'var(--viz-answered)', value: (total - blocked).toLocaleString() },
                { label: 'Blocked', color: 'var(--viz-blocked)', value: `${blocked.toLocaleString()}${total ? ` (${((100 * blocked) / total).toFixed(1)}%)` : ''}` },
            ]} />
            <AreaChart points={points} keys={QUERY_KEYS} step="10 minutes" label="Answered and blocked queries per 10 minutes, last 24 hours" />
        </>
    );
}

function ClientsChart({ clients }: { clients: Traffic['clients'] }) {
    if (!clients.keys.length) return <Empty>No clients in the query log yet (or the privacy level keeps none).</Empty>;
    const keys = clients.keys.map((k, i) => ({ key: k, label: k, color: seriesColor(i, k) }));
    const points = clients.series.map(({ hour, ...rest }) => ({ time: hour, ...rest }));
    return (
        <>
            <Legend items={keys.map((k) => ({ label: k.label, color: k.color }))} />
            <AreaChart points={points} keys={keys} step="1 hour" label="Queries per hour from the busiest clients, last 24 hours" height={200} />
        </>
    );
}

function Traffic({ traffic }: { traffic: Traffic }) {
    const empty = 'Nothing in the query log yet.';
    return (
        <>
            <Panel title="Clients over the last 24 hours" className="viz-panel" actions={<Link href="/queries?view=top">Top lists</Link>}>
                <ClientsChart clients={traffic.clients} />
            </Panel>
            <div className="viz-row">
                <Panel title="Query types"><Donut rows={traffic.qtype} label="Query types, last 24 hours" center="queries" /></Panel>
                <Panel title="Replies"><Donut rows={traffic.rcode} label="Reply codes, last 24 hours" center="replies" /></Panel>
                <Panel title="Answers"><Donut rows={traffic.status} label="Answered, blocked and allowed queries, last 24 hours" center="queries" names={STATUS_NAMES} colors={STATUS_COLORS} /></Panel>
            </div>
            <div className="viz-row">
                <Panel title="Top domains"><BarList rows={traffic.top_domains} color="var(--viz-answered)" empty={empty} href={(d) => `/queries?domain=${encodeURIComponent(d)}`} /></Panel>
                <Panel title="Top blocked domains"><BarList rows={traffic.top_blocked} color="var(--viz-blocked)" empty="Nothing blocked in the last 24 hours." href={(d) => `/queries?domain=${encodeURIComponent(d)}&status=blocked`} /></Panel>
                <Panel title="Top clients"><BarList rows={traffic.top_clients} color="var(--viz-1)" empty={empty} href={(c) => `/queries?client=${encodeURIComponent(c)}`} /></Panel>
            </div>
        </>
    );
}

export default function Dashboard() {
    const can = useCan();
    const { clock } = useShared();
    const dash = useApi<DashboardData>('/api/dashboard');
    const health = useApi<Health>('/api/system/health');
    const alerts = useApi<{ active: Alert[] }>('/api/alerts');
    const open = alerts.data?.active ?? [];

    return (
        <AppLayout title="Dashboard">
            <div className="workspace-intro">
                <div className="workspace-actions">
                    {can('zones.create') && <Link className="button primary" href="/zones/new"><Icon name="plus" />New zone</Link>}
                    {can('rpz.manage') && <Link className="button" href="/blocking?tab=rules">Block or allow a domain</Link>}
                </div>
            </div>
            {dash.error && <div className="flash danger">{dash.error.message}</div>}
            {open.length > 0 && (
                <div className={`flash ${open.some((a) => a.severity === 'error') ? 'danger' : 'warning'}`} role="status">
                    <strong>{open.length} open problem{open.length === 1 ? '' : 's'}</strong>{' '}
                    {open.slice(0, 3).map((a) => `${a.title} (${a.node})`).join(', ')}{open.length > 3 ? ', …' : ''}
                    {can('system.manage') && <> · <Link href="/settings?tab=alerts">Alerts</Link></>}
                </div>
            )}
            {dash.data && (
                <LivePanel title="Key figures" url="/api/dashboard" interval={60} initial={dash.data} className="live-bare" render={(d) => <MetricCards metrics={d.metrics} />} />
            )}
            {health.data && (
                <LivePanel title="Service health" url="/api/system/health" interval={30} initial={health.data} className="viz-panel" render={(h) => <HealthBoard health={h} />} />
            )}
            {dash.data && (
                <LivePanel title="Queries over the last 24 hours" url="/api/dashboard" interval={60} initial={dash.data} className="viz-panel" render={(d) => <QueriesChart series={d.series} />} />
            )}
            {dash.data?.traffic && <Traffic traffic={dash.data.traffic} />}
            <div className="dashboard-grid">
                {dash.data && (
                    <Panel title="Recent changes" actions={can('audit.view') ? <Link href="/audit">Audit log</Link> : undefined}>
                        {dash.data.recent.length ? (
                            <DataTable
                                rows={dash.data.recent}
                                rowKey={(r) => r.id}
                                columns={[
                                    { header: 'Time', cell: (r) => <Time value={r.created_at} timezone={clock.timezone} /> },
                                    { header: 'Operator', cell: (r) => r.actor },
                                    { header: 'Change', cell: (r) => <Badge>{r.action}</Badge> },
                                    { header: 'Item', className: 'cell-wrap', cell: (r) => r.summary },
                                ]}
                            />
                        ) : <Empty>No changes yet.</Empty>}
                    </Panel>
                )}
            </div>
        </AppLayout>
    );
}
