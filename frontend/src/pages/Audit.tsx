import { Link, router, usePage } from '@inertiajs/react';
import { useState } from 'react';
import { DataTable, Pagination } from '@/components/table';
import { Badge, ListPanel, Time } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { searchOf, useApi } from '@/lib/api';
import { useShared } from '@/lib/auth';
import { query } from '@/lib/format';
import type { Paginated } from '@/lib/types';

type Entry = { id: number; actor: string; action: string; entity: string; entity_id: string; payload: unknown; ip: string; created_at: string; summary: string };
type Result = Paginated<Entry> & { entities: string[]; actors: string[] };
type Filters = { q: string; actor: string; entity: string; from: string; to: string };

const TONE = (action: string) => (action.endsWith('deleted') || action.endsWith('failed') ? 'danger' : action.endsWith('created') ? 'success' : '');

export default function Audit() {
    const { clock } = useShared();
    const { url } = usePage();
    const params = searchOf(url);
    const filters: Filters = { q: params.get('q') ?? '', actor: params.get('actor') ?? '', entity: params.get('entity') ?? '', from: params.get('from') ?? '', to: params.get('to') ?? '' };
    const { data, error } = useApi<Result>(`/api/audit${query({ ...filters, page: params.get('page') ?? '' })}`);
    const [values, setValues] = useState(filters);
    const apply = (next: Filters) => router.get('/audit', Object.fromEntries(Object.entries(next).filter(([, v]) => v)), { preserveScroll: true });
    const set = (key: keyof Filters, value: string, now = false) => {
        const next = { ...values, [key]: value };
        setValues(next);
        if (now) apply(next);
    };

    return (
        <AppLayout title="Audit log">
            <div className="clean-list">
                <ListPanel title="Every change, by whom" description={data ? `${data.total.toLocaleString()} matching entries` : 'Loading…'}>
                    <form className="toolbar list-filterbar" role="search" onSubmit={(e) => { e.preventDefault(); apply(values); }}>
                        <label className="list-search"><span>Search</span><input type="search" placeholder="Zone, domain, user or ID" value={values.q} onChange={(e) => set('q', e.target.value)} /></label>
                        <label className="list-filter"><span>Operator</span>
                            <select value={values.actor} onChange={(e) => set('actor', e.target.value, true)}>
                                <option value="">Everyone</option>
                                {data?.actors.map((a) => <option key={a}>{a}</option>)}
                            </select>
                        </label>
                        <label className="list-filter"><span>Item</span>
                            <select value={values.entity} onChange={(e) => set('entity', e.target.value, true)}>
                                <option value="">All items</option>
                                {data?.entities.map((a) => <option key={a}>{a}</option>)}
                            </select>
                        </label>
                        <label className="list-filter"><span>From</span><input type="date" value={values.from} onChange={(e) => set('from', e.target.value, true)} /></label>
                        <label className="list-filter"><span>To</span><input type="date" value={values.to} onChange={(e) => set('to', e.target.value, true)} /></label>
                        <div className="list-filter-buttons">
                            <button>Filter</button>
                            {Object.values(filters).some(Boolean) && <Link className="button" href="/audit">Clear</Link>}
                        </div>
                    </form>
                    {error && <div className="flash danger">{error.message}</div>}
                    {data && (
                        <>
                            <DataTable
                                rows={data.rows}
                                rowKey={(r) => r.id}
                                serverPaginated
                                exportRows
                                resetHref="/audit"
                                columns={[
                                    { header: 'Time', cell: (r) => <Time value={r.created_at} timezone={clock.timezone} /> },
                                    { header: 'Operator', cell: (r) => <div className="list-cell-stack"><span>{r.actor}</span>{r.ip && <span className="list-subline mono">{r.ip}</span>}</div> },
                                    { header: 'Action', cell: (r) => <Badge tone={TONE(r.action)}>{r.action}</Badge> },
                                    { header: 'Item', cell: (r) => <div className="list-cell-stack"><span>{r.summary || '-'}</span><span className="list-subline">{r.entity} {r.entity_id}</span></div> },
                                    { header: 'Details', className: 'cell-wrap', cell: (r) => (r.payload ? <pre className="audit-payload">{JSON.stringify(r.payload, null, 1)}</pre> : '-') },
                                ]}
                            />
                            <Pagination result={data} path="/audit" query={filters} noun="entries" />
                        </>
                    )}
                </ListPanel>
            </div>
        </AppLayout>
    );
}
