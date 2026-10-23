import { router } from '@inertiajs/react';
import { Fragment, useState, type KeyboardEvent } from 'react';
import { useConfirm } from '@/components/confirm';
import { useToast } from '@/components/dns/feedback';
import { Pagination } from '@/components/table';
import { Badge } from '@/components/ui';
import { ApiError, del, patch, post, useApi } from '@/lib/api';
import { query } from '@/lib/format';
import type { Paginated } from '@/lib/types';

export type RecordRow = { id: number; name: string; fqdn: string; type: string; value: string; ttl: number | null; priority: number | null; disabled: boolean; comment: string };
type Draft = { name: string; type: string; value: string; ttl: string; priority: string; comment: string };

const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'PTR', 'DS', 'TLSA', 'SSHFP', 'NAPTR', 'HTTPS', 'SVCB'];
const PLACEHOLDER: Record<string, string> = {
    A: '192.0.2.10', AAAA: '2001:db8::10', CNAME: 'target.example.net', MX: 'mail.example.com', TXT: 'v=spf1 mx -all',
    NS: 'ns1.example.net', SRV: 'weight port target, e.g. 5 5060 sip', CAA: '0 issue "letsencrypt.org"', PTR: 'host.example.com',
    DS: 'key-tag algorithm digest-type digest, e.g. 12345 13 2 1F3C…', TLSA: 'usage selector type data, e.g. 3 1 1 0C72AC…',
    SSHFP: 'algorithm type fingerprint, e.g. 4 2 1234…', NAPTR: 'order pref "flags" "service" "regexp" replacement',
    HTTPS: 'priority target params, e.g. 1 . alpn=h2,h3', SVCB: 'priority target params, e.g. 1 svc.example.net alpn=h2',
};
const HAS_PRIORITY = (type: string) => type === 'MX' || type === 'SRV';
const EMPTY: Draft = { name: '', type: 'A', value: '', ttl: '', priority: '', comment: '' };

function toDraft(r: RecordRow): Draft {
    return { name: r.name, type: r.type, value: r.value, ttl: r.ttl === null ? '' : String(r.ttl), priority: r.priority === null ? '' : String(r.priority), comment: r.comment };
}

function body(d: Draft) {
    return {
        name: d.name.trim() || '@', type: d.type, value: d.value, comment: d.comment,
        ttl: d.ttl.trim() ? Number(d.ttl) : null, priority: HAS_PRIORITY(d.type) && d.priority.trim() ? Number(d.priority) : null,
    };
}

/** One editable row: inputs for every field; Enter saves, Escape cancels. */
function EditCells({ draft, setDraft, errors, onSave, onCancel, saveLabel, busy }: {
    draft: Draft; setDraft: (d: Draft) => void; errors: Record<string, string>; onSave: () => void; onCancel?: () => void; saveLabel: string; busy: boolean;
}) {
    const keys = (event: KeyboardEvent) => {
        if (event.key === 'Enter') { event.preventDefault(); onSave(); }
        if (event.key === 'Escape' && onCancel) { event.preventDefault(); onCancel(); }
    };
    const input = (field: keyof Draft, label: string, extra: Record<string, unknown> = {}) => (
        <input aria-label={label} aria-invalid={errors[field] ? true : undefined} value={draft[field]} onKeyDown={keys} onChange={(e) => setDraft({ ...draft, [field]: e.target.value })} spellCheck={false} autoComplete="off" {...extra} />
    );
    return (
        <>
            <td>{input('name', 'Name', { placeholder: '@' })}</td>
            <td>
                <select aria-label="Type" value={draft.type} onKeyDown={keys} onChange={(e) => setDraft({ ...draft, type: e.target.value })}>
                    {TYPES.map((t) => <option key={t}>{t}</option>)}
                </select>
            </td>
            <td className="cell-value">{input('value', 'Value', { placeholder: PLACEHOLDER[draft.type] })}</td>
            <td className="cell-prio">{HAS_PRIORITY(draft.type) ? input('priority', 'Priority', { inputMode: 'numeric', placeholder: '10' }) : <span className="list-subline">–</span>}</td>
            <td className="cell-ttl">{input('ttl', 'TTL', { inputMode: 'numeric', placeholder: 'default' })}</td>
            <td>{input('comment', 'Comment', { placeholder: 'optional' })}</td>
            <td>
                <div className="inline-actions">
                    <button type="button" className="primary" disabled={busy} onClick={onSave}>{saveLabel}</button>
                    {onCancel && <button type="button" onClick={onCancel}>Cancel</button>}
                </div>
            </td>
        </>
    );
}

function ErrorRow({ errors }: { errors: Record<string, string> }) {
    const messages = [...new Set(Object.values(errors))];
    if (!messages.length) return null;
    return <tr className="row-error"><td colSpan={7} role="alert">{messages.join(' ')}</td></tr>;
}

export function RecordsTable({ zoneId, zoneName, defaultTtl, canManage, filters, onChanged }: {
    zoneId: number; zoneName: string; defaultTtl: number; canManage: boolean; filters: { q: string; type: string; page: string }; onChanged: () => void;
}) {
    const ask = useConfirm();
    const toast = useToast();
    const { data, setData, error } = useApi<Paginated<RecordRow>>(`/api/zones/${zoneId}/records${query({ q: filters.q, type: filters.type, page: filters.page, size: 100 })}`);
    const [adding, setAdding] = useState<Draft>(EMPTY);
    const [addErrors, setAddErrors] = useState<Record<string, string>>({});
    const [editing, setEditing] = useState<{ id: number; draft: Draft } | null>(null);
    const [editErrors, setEditErrors] = useState<Record<string, string>>({});
    const [pending, setPending] = useState<number[]>([]);
    const [busy, setBusy] = useState(false);
    const [q, setQ] = useState(filters.q);

    const replaceRow = (row: RecordRow) => data && setData({ ...data, rows: data.rows.map((r) => (r.id === row.id ? row : r)) });
    const errorsOf = (e: unknown) => {
        const err = e as ApiError;
        return Object.keys(err.errors).length ? err.errors : { value: err.message };
    };

    const add = async () => {
        if (!data) return;
        setBusy(true);
        setAddErrors({});
        try {
            const row = await post<RecordRow>(`/api/zones/${zoneId}/records`, body(adding));
            setData({ ...data, rows: [row, ...data.rows], total: data.total + 1 });
            setAdding({ ...EMPTY, type: adding.type });
            toast(`${row.type} record for ${row.fqdn} added.`);
            onChanged();
        } catch (e) {
            setAddErrors(errorsOf(e));
        } finally {
            setBusy(false);
        }
    };

    const save = async () => {
        if (!editing || !data) return;
        const original = data.rows.find((r) => r.id === editing.id)!;
        const b = body(editing.draft);
        // Optimistic: show the new values right away, greyed until the server confirms.
        replaceRow({ ...original, ...b, ttl: b.ttl, priority: b.priority });
        setPending((p) => [...p, editing.id]);
        setBusy(true);
        try {
            const row = await patch<RecordRow>(`/api/zones/${zoneId}/records/${editing.id}`, { ...b, clear_ttl: b.ttl === null });
            replaceRow(row);
            setEditing(null);
            setEditErrors({});
            toast(`${row.type} record for ${row.fqdn} saved.`);
            onChanged();
        } catch (e) {
            replaceRow(original);
            setEditErrors(errorsOf(e));
        } finally {
            setPending((p) => p.filter((id) => id !== editing.id));
            setBusy(false);
        }
    };

    const toggle = async (r: RecordRow) => {
        replaceRow({ ...r, disabled: !r.disabled });
        try {
            replaceRow(await patch<RecordRow>(`/api/zones/${zoneId}/records/${r.id}`, { disabled: !r.disabled }));
            toast(`${r.type} record for ${r.fqdn} ${r.disabled ? 'enabled' : 'disabled'}.`);
            onChanged();
        } catch (e) {
            replaceRow(r);
            toast((e as ApiError).message, 'danger');
        }
    };

    const remove = async (r: RecordRow) => {
        const ok = await ask({ title: 'Delete record?', message: `${r.fqdn} ${r.type} ${r.priority ?? ''} ${r.value}\n\nThe record is removed from the zone and BIND reloads it.`, confirmLabel: 'Delete record' });
        if (!ok || !data) return;
        const previous = data;
        setData({ ...data, rows: data.rows.filter((x) => x.id !== r.id), total: data.total - 1 });
        try {
            await del(`/api/zones/${zoneId}/records/${r.id}`);
            toast(`${r.type} record for ${r.fqdn} deleted.`);
            onChanged();
        } catch (e) {
            setData(previous);
            toast((e as ApiError).message, 'danger');
        }
    };

    return (
        <>
            <form className="toolbar list-filterbar" role="search" onSubmit={(e) => { e.preventDefault(); router.get(`/zones/${zoneId}`, { q, type: filters.type }, { preserveScroll: true }); }}>
                <label className="list-search">
                    <span>Search records</span>
                    <input type="search" placeholder="Name, value or comment" value={q} onChange={(e) => setQ(e.target.value)} />
                </label>
                <label className="list-filter">
                    <span>Type</span>
                    <select value={filters.type} onChange={(e) => router.get(`/zones/${zoneId}`, { q, type: e.target.value }, { preserveScroll: true })}>
                        <option value="">All types</option>
                        {TYPES.map((t) => <option key={t}>{t}</option>)}
                    </select>
                </label>
                <div className="list-filter-buttons"><button>Filter</button></div>
            </form>
            {error && <div className="flash danger">{error.message}</div>}
            <div className="table-wrap">
                <table className="records-table">
                    <thead>
                        <tr>
                            <th scope="col">Name</th><th scope="col">Type</th><th scope="col">Value</th><th scope="col">Priority</th>
                            <th scope="col">TTL</th><th scope="col">Comment</th><th scope="col">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {canManage && (
                            <>
                                <tr className="add-row">
                                    <EditCells draft={adding} setDraft={setAdding} errors={addErrors} onSave={() => void add()} saveLabel="Add record" busy={busy} />
                                </tr>
                                <ErrorRow errors={addErrors} />
                            </>
                        )}
                        {data && !data.rows.length && <tr><td colSpan={7} className="empty">{filters.q || filters.type ? 'No records match these filters.' : 'No records yet.'}</td></tr>}
                        {data?.rows.map((r) => editing?.id === r.id ? (
                            <Fragment key={r.id}>
                                <tr className="is-editing">
                                    <EditCells draft={editing.draft} setDraft={(d) => setEditing({ id: r.id, draft: d })} errors={editErrors} onSave={() => void save()} onCancel={() => { setEditing(null); setEditErrors({}); }} saveLabel="Save" busy={busy} />
                                </tr>
                                <ErrorRow errors={editErrors} />
                            </Fragment>
                        ) : (
                            <tr key={r.id} className={[r.disabled ? 'is-disabled' : '', pending.includes(r.id) ? 'is-pending' : ''].join(' ').trim() || undefined}>
                                <td data-label="Name"><span title={r.fqdn}>{r.name}</span></td>
                                <td data-label="Type"><Badge>{r.type}</Badge></td>
                                <td data-label="Value" className="cell-value">{r.value}</td>
                                <td data-label="Priority" className={r.priority === null ? 'is-empty' : undefined}>{r.priority ?? '-'}</td>
                                <td data-label="TTL" title={r.ttl === null ? `Zone default (${defaultTtl})` : undefined}>{r.ttl ?? <span className="list-subline">{defaultTtl}</span>}</td>
                                <td data-label="Comment" className="cell-wrap">{r.comment || <span className="list-subline">–</span>}</td>
                                <td data-label="Actions">
                                    {canManage ? (
                                        <div className="inline-actions">
                                            <button type="button" className="link" onClick={() => { setEditing({ id: r.id, draft: toDraft(r) }); setEditErrors({}); }}>Edit</button>
                                            <button type="button" className="link" onClick={() => void toggle(r)}>{r.disabled ? 'Enable' : 'Disable'}</button>
                                            <button type="button" className="link danger-text" onClick={() => void remove(r)}>Delete</button>
                                        </div>
                                    ) : r.disabled ? <Badge>disabled</Badge> : null}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
            {data && <Pagination result={data} path={`/zones/${zoneId}`} query={{ q: filters.q, type: filters.type }} noun="records" />}
            <p className="hint records-hint">
                Names are relative to {zoneName} (@ is the zone itself). In values, a single word such as <code>mail</code> means mail.{zoneName}; anything with a dot is a full name.
            </p>
        </>
    );
}
