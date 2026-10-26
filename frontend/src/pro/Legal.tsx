// SPDX-License-Identifier: Elastic-2.0
// DNSOne Pro (LICENSE-PRO): on with a licence key, Settings → License.
// Court-ordered blocking: the list, adding an order, lifting, the notice page, the regulator's export.
import { router, usePage } from '@inertiajs/react';
import { useState } from 'react';
import { DownloadLink } from '@/components/confirm';
import { FormDialog, useToast } from '@/components/dns/feedback';
import Icon from '@/components/Icon';
import { DataTable, Pagination } from '@/components/table';
import { Tabs } from '@/components/tabs';
import { Badge, Check, Empty, ErrorSummary, Field, FormActions, HealthItem, ListPanel, Panel, TextArea } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { ApiError, post, put, searchOf, useApi } from '@/lib/api';
import { useCan } from '@/lib/auth';
import { query } from '@/lib/format';
import type { Paginated } from '@/lib/types';

type Entry = {
    id: number; pattern: string; authority: string; reference: string; ordered_on: string | null; notes: string; active: boolean;
    created_by: string; created_at: string; lifted_at: string | null; lifted_by: string | null; lift_reason: string | null;
};
type Page = { address4: string; address6: string; title: string; message: string; show_reference: boolean };
type List = Paginated<Entry> & { summary: { active: number; orders: number; triggers: number | null; pending: boolean; page: Page } };

function errorsOf(e: unknown, fallback: string): Record<string, string> {
    const ae = e as ApiError;
    return Object.keys(ae.errors).length ? ae.errors : { [fallback]: ae.message };
}

function LiftDialog({ target, onClose, onDone }: { target: Entry | { reference: string } | null; onClose: () => void; onDone: () => void }) {
    const toast = useToast();
    const [reason, setReason] = useState('');
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);
    if (!target) return null;
    const one = 'id' in target;
    return (
        <FormDialog open title={one ? `Lift the block of ${target.pattern}?` : `Lift every block of order ${target.reference}?`} submitLabel="Lift" busy={busy} onClose={onClose} onSubmit={async () => {
            setBusy(true);
            try {
                if (one) {
                    await post(`/api/legal/${target.id}/lift`, { reason });
                    toast(`${target.pattern} is no longer blocked. Customers resolve it again within a minute.`);
                } else {
                    const r = await post<{ lifted: number }>('/api/legal/lift-order', { reference: target.reference, reason });
                    toast(`${r.lifted} name(s) of order ${target.reference} lifted.`);
                }
                onDone();
            } catch (e) {
                setError((e as ApiError).message);
            } finally {
                setBusy(false);
            }
        }}>
            <p>The entry stays in the list as lifted, with this reason, for the record.</p>
            <div className="form-grid">
                <Field label="Reason" name="reason" className="span2" required minLength={3} placeholder="Order revoked on appeal, decision no. …" value={reason} error={error || undefined} onChange={(e) => setReason(e.target.value)} />
            </div>
        </FormDialog>
    );
}

function Entries({ canManage }: { canManage: boolean }) {
    const { url } = usePage();
    const params = searchOf(url);
    const filters = { q: params.get('q') ?? '', status: params.get('status') ?? 'active', page: params.get('page') ?? '' };
    const api = { ...filters, status: filters.status === 'all' ? '' : filters.status };
    const { data, reload } = useApi<List>(`/api/legal${query(api)}`);
    const [q, setQ] = useState(filters.q);
    const [lifting, setLifting] = useState<Entry | { reference: string } | null>(null);
    if (!data) return <Empty>Loading…</Empty>;
    const go = (patch: Record<string, string>) => {
        const next = { ...filters, ...patch, page: '' };
        router.get('/legal', Object.fromEntries(Object.entries(next).filter(([, v]) => v !== '')), { preserveScroll: true });
    };
    return (
        <ListPanel title="Blocked by court order" description="Applies to every customer, whatever their group; ad-blocking rules, allowlists and pauses do not lift it."
            tools={<DownloadLink href={`/api/legal/export${query({ q: api.q, status: api.status })}`}>Export CSV</DownloadLink>}>
            <form className="toolbar list-filterbar" onSubmit={(e) => { e.preventDefault(); go({ q }); }}>
                <label className="list-search"><span>Search</span><input type="search" placeholder="Domain, reference or authority" value={q} onChange={(e) => setQ(e.target.value)} /></label>
                <label className="list-filter"><span>Status</span>
                    <select value={filters.status} onChange={(e) => go({ status: e.target.value })}>
                        <option value="active">Blocked now</option><option value="lifted">Lifted</option><option value="all">All</option>
                    </select>
                </label>
                <div className="list-filter-buttons"><button className="primary">Search</button></div>
            </form>
            <DataTable
                rows={data.rows}
                rowKey={(r) => r.id}
                serverPaginated
                emptyText={filters.status === 'active' ? 'Nothing is blocked by court order.' : 'No entries.'}
                columns={[
                    { header: 'Domain', cell: (r) => <div className="list-cell-stack"><span className="mono">{r.pattern}</span><span className="list-subline">{r.pattern.startsWith('*.') ? 'every name below it' : 'and every name below it'}</span></div> },
                    { header: 'Order', cell: (r) => <div className="list-cell-stack"><span>{r.reference}{r.ordered_on ? ` of ${r.ordered_on}` : ''}</span><span className="list-subline">{r.authority}</span></div> },
                    { header: 'Added', cell: (r) => <div className="list-cell-stack"><span className="mono">{r.created_at}</span><span className="list-subline">{r.created_by}</span></div> },
                    { header: 'Status', cell: (r) => (r.active ? <Badge tone="warning">blocked</Badge> : <div className="list-cell-stack"><Badge>lifted {r.lifted_at?.slice(0, 10)}</Badge><span className="list-subline">{r.lifted_by}: {r.lift_reason}</span></div>) },
                    ...(canManage ? [{
                        header: 'Actions', noExport: true, cell: (r: Entry) => (r.active ? (
                            <>
                                <button type="button" className="link" onClick={() => setLifting(r)}>Lift</button>{' '}
                                <button type="button" className="link" onClick={() => setLifting({ reference: r.reference })}>Lift whole order</button>
                            </>
                        ) : null),
                    }] : []),
                ]}
            />
            {data.pages > 1 && <Pagination result={data} path="/legal" query={filters} noun="entries" />}
            <LiftDialog key={lifting ? JSON.stringify(lifting) : ''} target={lifting} onClose={() => setLifting(null)} onDone={() => { setLifting(null); void reload(); }} />
        </ListPanel>
    );
}

function AddOrder({ onAdded }: { onAdded: () => void }) {
    const toast = useToast();
    const [form, setForm] = useState({ authority: '', reference: '', ordered_on: '', notes: '', patterns: '' });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    return (
        <Panel title="Add a court order">
            <p className="hint">Every name of the order is blocked for every customer within a minute. example.com blocks it and every name below it; *.example.com only the names below it.</p>
            <ErrorSummary errors={errors} />
            <form className="form-grid" onSubmit={async (e) => {
                e.preventDefault();
                setBusy(true);
                try {
                    const r = await post<{ added: number; already_blocked: string[] }>('/api/legal', { ...form, ordered_on: form.ordered_on || null });
                    setErrors({});
                    toast(`${r.added} name(s) blocked${r.already_blocked.length ? `; already blocked: ${r.already_blocked.slice(0, 5).join(', ')}` : ''}.`, r.already_blocked.length ? 'warning' : 'success');
                    setForm({ authority: form.authority, reference: '', ordered_on: '', notes: '', patterns: '' });
                    onAdded();
                } catch (err) {
                    setErrors(errorsOf(err, 'patterns'));
                } finally {
                    setBusy(false);
                }
            }}>
                <Field label="Ordered by" name="authority" required placeholder="Court of First Instance, Tirana" value={form.authority} error={errors.authority} onChange={(e) => setForm({ ...form, authority: e.target.value })} />
                <Field label="Reference" name="reference" required placeholder="Decision no. 1234/2026" value={form.reference} error={errors.reference} onChange={(e) => setForm({ ...form, reference: e.target.value })} />
                <Field label="Date of the order" name="ordered_on" type="date" value={form.ordered_on} error={errors.ordered_on} onChange={(e) => setForm({ ...form, ordered_on: e.target.value })} />
                <Field label="Notes" name="notes" value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
                <TextArea label="Domains, one per line" name="patterns" rows={8} spellCheck={false} required placeholder={'blocked-site.example\n*.mirror.example'} value={form.patterns} error={errors.patterns}
                    onChange={(e) => setForm({ ...form, patterns: e.target.value })} />
                <FormActions><button className="primary" disabled={busy}>Block these names</button></FormActions>
            </form>
        </Panel>
    );
}

function NoticePage({ page, canManage, onSaved }: { page: Page; canManage: boolean; onSaved: () => void }) {
    const toast = useToast();
    const [form, setForm] = useState(page);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    return (
        <Panel title="Legal notice page">
            <p className="hint">Blocked names answer with this page's address, so browsers show the notice (HTTP; HTTPS links show a connection error, as no certificate can match a blocked name). Without an address they answer "does not exist" (NXDOMAIN). Either way the answer carries Extended DNS Error 16 "Censored".</p>
            <ErrorSummary errors={errors} />
            <form className="form-grid" onSubmit={async (e) => {
                e.preventDefault();
                setBusy(true);
                try {
                    await put('/api/legal/page', form);
                    setErrors({});
                    toast('Notice page saved.');
                    onSaved();
                } catch (err) {
                    setErrors(errorsOf(err, 'title'));
                } finally {
                    setBusy(false);
                }
            }}>
                <Field label="Page address (IPv4)" name="address4" spellCheck={false} disabled={!canManage} placeholder="203.0.113.80" value={form.address4} error={errors.address4} onChange={(e) => setForm({ ...form, address4: e.target.value })} />
                <Field label="Page address (IPv6)" name="address6" spellCheck={false} disabled={!canManage} placeholder="2001:db8::80" value={form.address6} error={errors.address6} onChange={(e) => setForm({ ...form, address6: e.target.value })} />
                <Field label="Title" name="title" className="span2" required disabled={!canManage} value={form.title} error={errors.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
                <TextArea label="Message" name="message" rows={4} required disabled={!canManage} value={form.message} error={errors.message} onChange={(e) => setForm({ ...form, message: e.target.value })} />
                <div className="span2"><Check label="Show the authority and the reference of the order on the page" disabled={!canManage} checked={form.show_reference} onChange={(e) => setForm({ ...form, show_reference: e.target.checked })} /></div>
                <p className="span2 hint">The address must reach this server's nginx with the site <span className="mono">deploy/nginx/dnsone-legal.conf</span> (docs/RUNBOOK.md, "Court-ordered blocking").</p>
                {canManage && <FormActions><button className="primary" disabled={busy}>Save</button></FormActions>}
            </form>
        </Panel>
    );
}

export default function Legal() {
    const can = useCan();
    const canManage = can('legal.manage');
    const summary = useApi<List>('/api/legal?size=1');
    const s = summary.data?.summary;
    return (
        <AppLayout title="Court orders">
            {s && (
                <Panel>
                    <div className="health-grid">
                        <HealthItem label="Names blocked" value={s.active.toLocaleString()} />
                        <HealthItem label="Orders" value={s.orders.toLocaleString()} />
                        <HealthItem label="Answer" value={s.page.address4 || s.page.address6 ? `notice page ${[s.page.address4, s.page.address6].filter(Boolean).join(', ')}` : 'NXDOMAIN (no notice page)'} />
                        <HealthItem label="Resolvers" value={s.pending ? 'updating…' : 'up to date'} tone={s.pending ? 'info' : 'success'} />
                    </div>
                </Panel>
            )}
            <Tabs
                label="Court orders"
                tabs={[
                    { key: 'list', title: 'List', icon: 'shield', content: <Entries canManage={canManage} /> },
                    ...(canManage ? [{ key: 'add', title: 'Add an order', icon: 'plus', content: <AddOrder onAdded={() => void summary.reload()} /> }] : []),
                    { key: 'page', title: 'Notice page', icon: 'book', content: s ? <NoticePage page={s.page} canManage={canManage} onSaved={() => void summary.reload()} /> : <Empty>Loading…</Empty> },
                ]}
            />
            {!canManage && <p className="hint"><Icon name="lock" /> Your role can see this list; adding and lifting needs the legal.manage permission.</p>}
        </AppLayout>
    );
}
