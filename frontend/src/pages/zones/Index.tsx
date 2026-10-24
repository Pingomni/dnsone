import { Link, router, usePage } from '@inertiajs/react';
import { useEffect, useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { useToast } from '@/components/dns/feedback';
import { DnssecState, PublishState, type ZoneRow } from '@/components/dns/zone';
import Icon from '@/components/Icon';
import { DataTable, Pagination } from '@/components/table';
import { ListPanel, RowActions } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { del, searchOf, useApi } from '@/lib/api';
import { useCan } from '@/lib/auth';
import { query } from '@/lib/format';
import type { Option, Paginated } from '@/lib/types';

type Filters = { q: string; status: string; state: string; sort: string };
type Result = Paginated<ZoneRow> & { summary: { published: number; pending: number; error: number } };

const STATUSES: Option[] = [{ value: '', label: 'All zones' }, { value: 'active', label: 'Active' }, { value: 'disabled', label: 'Disabled' }];
const STATES: Option[] = [{ value: '', label: 'Any state' }, { value: 'published', label: 'Published' }, { value: 'pending', label: 'Publishing' }, { value: 'error', label: 'Publish failed' }];
const SORTS: Option[] = [{ value: 'name', label: 'Name' }, { value: '-updated_at', label: 'Recently changed' }, { value: 'state', label: 'Publish state' }];

function FilterBar({ filters }: { filters: Filters }) {
    const [values, setValues] = useState(filters);
    const apply = (next: Filters) => router.get('/zones', Object.fromEntries(Object.entries(next).filter(([k, v]) => v !== '' && !(k === 'sort' && v === 'name'))), { preserveScroll: true });
    const select = (name: keyof Filters, label: string, options: Option[]) => (
        <label className="list-filter">
            <span>{label}</span>
            <select name={name} value={values[name]} onChange={(e) => { const next = { ...values, [name]: e.target.value }; setValues(next); apply(next); }}>
                {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
        </label>
    );
    return (
        <form className="toolbar list-filterbar" role="search" onSubmit={(e) => { e.preventDefault(); apply(values); }}>
            <label className="list-search">
                <span>Search zones</span>
                <input type="search" name="q" aria-label="Search zones" placeholder="Domain or description" value={values.q} onChange={(e) => setValues({ ...values, q: e.target.value })} />
            </label>
            {select('status', 'Status', STATUSES)}
            {select('state', 'Publish state', STATES)}
            {select('sort', 'Sort by', SORTS)}
            <div className="list-filter-buttons">
                <button>Filter</button>
                {(filters.q || filters.status || filters.state) && <Link className="button" href="/zones">Clear</Link>}
            </div>
        </form>
    );
}

export default function Zones() {
    const can = useCan();
    const ask = useConfirm();
    const toast = useToast();
    const { url } = usePage();
    const params = searchOf(url);
    const filters: Filters = { q: params.get('q') ?? '', status: params.get('status') ?? '', state: params.get('state') ?? '', sort: params.get('sort') ?? 'name' };
    const page = params.get('page') ?? '';
    const { data, setData, error, reload } = useApi<Result>(`/api/zones${query({ ...filters, page })}`);
    // Zones are published in the background: refresh while any is still on its way to BIND.
    const publishing = Boolean(data?.rows.some((r) => r.status === 'active' && (r.publish_state === 'pending' || r.pending)));
    useEffect(() => {
        if (!publishing) return;
        const timer = window.setTimeout(() => void reload(), 2000);
        return () => window.clearTimeout(timer);
    }, [publishing, data, reload]);

    const remove = async (zone: ZoneRow) => {
        const ok = await ask({
            title: `Delete zone ${zone.name}?`,
            message: `BIND stops answering for ${zone.name} and its ${zone.record_count ?? 0} records are deleted. This cannot be undone.`,
            confirmLabel: 'Delete zone',
            typeToConfirm: zone.name,
        });
        if (!ok || !data) return;
        // Optimistic: drop the row, put it back if the server refuses.
        const previous = data;
        setData({ ...data, rows: data.rows.filter((r) => r.id !== zone.id), total: data.total - 1 });
        try {
            await del(`/api/zones/${zone.id}`);
            toast(`Zone ${zone.name} deleted.`);
            router.reload();
        } catch (e) {
            setData(previous);
            toast((e as Error).message, 'danger');
        }
    };

    return (
        <AppLayout title="Zones">
            <div className="clean-list">
                <ListPanel
                    title="Authoritative zones"
                    description={data ? `${data.total} matching ${data.total === 1 ? 'zone' : 'zones'} · ${data.summary.published} published, ${data.summary.pending} publishing, ${data.summary.error} failed` : 'Loading…'}
                    tools={<>{can('templates.manage') && <Link className="button" href="/templates">Templates</Link>}{can('zones.create') && <><Link className="button" href="/zones/import">Import zone</Link><Link className="button primary" href="/zones/new"><Icon name="plus" />New zone</Link></>}</>}
                >
                    <FilterBar key={JSON.stringify(filters)} filters={filters} />
                    {error && <div className="flash danger">{error.message}</div>}
                    {data && (
                        <>
                            <DataTable
                                rows={data.rows}
                                rowKey={(r) => r.id}
                                serverPaginated
                                exportRows
                                resetHref="/zones"
                                emptyText={filters.q || filters.status || filters.state ? 'No zones match these filters.' : 'No zones yet. Create the first one with New zone.'}
                                columns={[
                                    { header: 'Zone', cell: (r) => <div className="list-cell-stack"><Link href={`/zones/${r.id}`}>{r.name}</Link>{r.description && <span className="list-subline">{r.description}</span>}</div> },
                                    { header: 'State', cell: (r) => <><PublishState zone={r} /> <DnssecState zone={r} /></> },
                                    { header: 'Records', cell: (r) => r.record_count },
                                    { header: 'Serial', cell: (r) => <span className="mono">{r.published_serial ?? '-'}</span> },
                                    { header: 'Default TTL', cell: (r) => r.default_ttl },
                                    { header: 'Changed', cell: (r) => <span className="mono">{r.updated_at}</span> },
                                    {
                                        header: 'Actions',
                                        noExport: true,
                                        cell: (r) => (
                                            <RowActions label={`Actions for ${r.name}`}>
                                                <Link href={`/zones/${r.id}`}>{can('zones.manage') ? 'Edit records' : 'View records'}</Link>
                                                {can('zones.create') && <button type="button" className="link danger-text" onClick={() => void remove(r)}>Delete zone</button>}
                                            </RowActions>
                                        ),
                                    },
                                ]}
                            />
                            <Pagination result={data} path="/zones" query={filters} noun="zones" />
                        </>
                    )}
                </ListPanel>
            </div>
        </AppLayout>
    );
}
