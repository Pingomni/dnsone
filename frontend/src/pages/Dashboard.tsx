import { Link } from '@inertiajs/react';
import Icon from '@/components/Icon';
import { LivePanel } from '@/components/LivePanel';
import { MetricCards, type Metric } from '@/components/metrics';
import { DataTable } from '@/components/table';
import { Badge, Empty, HealthItem, Panel, Time } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { useApi } from '@/lib/api';
import { useCan, useShared } from '@/lib/auth';

type Hour = { hour: string; queries: number; blocked: number };
type Recent = { id: number; actor: string; action: string; entity: string; summary: string; created_at: string };
type DashboardData = { metrics: Metric[]; series: Hour[]; recent: Recent[] };
type Check = { name: string; status: 'ok' | 'warning' | 'error'; detail: string };
type Health = { status: string; checks: Check[] };
type Alert = { key: string; severity: 'error' | 'warning'; title: string; detail: string; since: string; node: string };

const TONE = { ok: 'success', warning: 'warning', error: 'danger' } as const;

function HealthGrid({ health }: { health: Health }) {
    return (
        <div className="health-grid">
            {health.checks.map((c) => (
                <HealthItem key={c.name} label={c.name} value={<><Badge tone={TONE[c.status]}>{c.status === 'ok' ? 'ok' : c.status}</Badge> <span className="list-subline">{c.detail}</span></>} />
            ))}
        </div>
    );
}

function HourBars({ series }: { series: Hour[] }) {
    const max = Math.max(1, ...series.map((h) => h.queries));
    if (!series.some((h) => h.queries)) return <Empty>No query statistics yet. They appear a few minutes after dnsone-stats.timer starts.</Empty>;
    return (
        <>
            <div className="hour-bars" style={{ '--bars': series.length } as React.CSSProperties} role="img" aria-label="Queries and blocked queries per hour, last 24 hours">
                {series.map((h) => (
                    <div key={h.hour} title={`${h.hour.slice(11, 16)} UTC: ${h.queries.toLocaleString()} queries, ${h.blocked.toLocaleString()} blocked`}>
                        <span style={{ height: `${((h.queries - h.blocked) / max) * 100}%` }} />
                        <span className="blocked" style={{ height: `${(h.blocked / max) * 100}%` }} />
                    </div>
                ))}
            </div>
            <div className="hour-legend"><span><i />Answered</span><span><i className="blocked" />Blocked</span><span>Peak {max.toLocaleString()} queries / hour</span></div>
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
            <div className="dashboard-grid">
                {health.data && (
                    <LivePanel title="Service health" url="/api/system/health" interval={30} initial={health.data} render={(h) => <HealthGrid health={h} />} />
                )}
                {dash.data && (
                    <Panel title="Queries, last 24 hours">
                        <HourBars series={dash.data.series} />
                    </Panel>
                )}
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
